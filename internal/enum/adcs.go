package enum

// adcs.go — Active Directory Certificate Services enumeration via ADWS.
//
// OPSEC strategy vs Certipy:
//   - Certipy sends complex bitmask LDAP filters over port 389 (signatured).
//   - We pull raw template/CA objects via ADWS (port 9389) with simple
//     objectClass filters, then do ALL ESC analysis client-side in Go.
//   - The ADWS query pattern looks identical to a generic config container dump.

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"spectral/internal/adws"
)

// ── EKU OIDs that allow domain authentication ─────────────────────────────

var authEKUs = map[string]string{
	"1.3.6.1.5.5.7.3.2":       "Client Authentication",
	"1.3.6.1.5.2.3.4":         "PKINIT Client Auth",
	"1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
	"2.5.29.37.0":              "Any Purpose",
}

const (
	ekuAnyPurpose    = "2.5.29.37.0"
	ekuCertReqAgent  = "1.3.6.1.4.1.311.20.2.1"

	// msPKI-Certificate-Name-Flag bits
	ctFlagEnrolleeSuppliesSubject = 0x00000001

	// msPKI-Enrollment-Flag bits
	ctFlagPendAllRequests   = 0x00000002
	ctFlagNoSecurityExt     = 0x00080000 // ESC9

	// msPKI-Private-Key-Flag bits
	ctFlagExportableKey     = 0x00000010
)

// ── Result types ─────────────────────────────────────────────────────────

// ADCSResult is the top-level output for -m adcs.
type ADCSResult struct {
	CAs       []CAInfo        `json:"cas"`
	Templates []TemplateInfo  `json:"templates"`
	RootCAs   []adws.ADObject `json:"root_cas"`
	NTAuth    []adws.ADObject `json:"ntauth"`
	Findings  []ESCFinding    `json:"findings"`
}

// CAInfo holds an enterprise CA and the names of templates it publishes.
type CAInfo struct {
	Object    adws.ADObject `json:"object"`
	Templates []string      `json:"published_templates"`
}

// TemplateInfo holds a template object with parsed flag values for analysis.
type TemplateInfo struct {
	Object      adws.ADObject `json:"object"`
	NameFlag    int64         `json:"name_flag"`
	EnrollFlag  int64         `json:"enroll_flag"`
	PrivKeyFlag int64         `json:"privkey_flag"`
	RASignature int64         `json:"ra_signature"`
	EKUs        []string      `json:"ekus"`
	AppPolicies []string      `json:"app_policies"`
}

// ESCFinding is a potential misconfiguration.
type ESCFinding struct {
	ESC         string `json:"esc"`
	Template    string `json:"template,omitempty"`
	CA          string `json:"ca,omitempty"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
	Note        string `json:"note,omitempty"`
}

// ── Attribute lists ───────────────────────────────────────────────────────

var caAttrs = []string{
	"cn",
	"distinguishedName",
	"dNSHostName",
	"cACertificateDN",
	"certificateTemplates",
	"flags",
	"cACertificate",
	"nTSecurityDescriptor",
	"objectGUID",
	"whenCreated",
}

var templateAttrs = []string{
	"cn",
	"displayName",
	"distinguishedName",
	"objectGUID",
	"flags",
	"revision",
	"msPKI-Certificate-Name-Flag",
	"msPKI-Enrollment-Flag",
	"msPKI-Private-Key-Flag",
	"msPKI-RA-Signature",
	"msPKI-Minimal-Key-Size",
	"msPKI-Certificate-Application-Policy",
	"pKIExtendedKeyUsage",
	"pKIExpirationPeriod",
	"pKIOverlapPeriod",
	"pKIDefaultCSPs",
	"nTSecurityDescriptor",
	"whenCreated",
}

var rootCAAttrs = []string{
	"cn",
	"distinguishedName",
	"cACertificate",
	"whenCreated",
}

// ── Main entry point ──────────────────────────────────────────────────────

// ADCS enumerates the full AD CS landscape and analyses for ESC misconfigs.
// All ESC logic runs client-side — the ADWS queries are plain objectClass
// lookups that match normal admin enumeration patterns.
func (e *Enumerator) ADCS() (*ADCSResult, error) {
	configDN := configNC(e.baseDN)
	pkiBase := "CN=Public Key Services,CN=Services," + configDN

	result := &ADCSResult{}
	var err error

	// 1. Enterprise CAs (Enrollment Services)
	// Query from pkiBase with ScopeSubtree rather than from the specific
	// CN=Enrollment Services container — some DCs return an LDAP referral
	// when the base DN points deep into the Configuration NC via ADWS.
	if e.verbose {
		log.Printf("[*] ADCS: enterprise CAs")
	}
	caObjs, err := e.client.Query(
		pkiBase,
		"(objectClass=pKIEnrollmentService)",
		caAttrs,
		adws.ScopeSubtree,
	)
	if err != nil {
		log.Printf("[*] ADCS: enterprise CAs unavailable")
	}
	for _, obj := range caObjs {
		templates := attrSlice(obj, "certificateTemplates")
		result.CAs = append(result.CAs, CAInfo{Object: obj, Templates: templates})
	}
	if e.verbose {
		log.Printf("[+] ADCS: %d enterprise CA(s)", len(result.CAs))
	}

	e.pace.BetweenRequests()

	// 2. Certificate Templates
	if e.verbose {
		log.Printf("[*] ADCS: certificate templates")
	}
	tmplObjs, err := e.client.Query(
		pkiBase,
		"(objectClass=pKIcertificateTemplate)",
		templateAttrs,
		adws.ScopeSubtree,
	)
	if err != nil {
		return nil, fmt.Errorf("adcs templates: %w", err)
	}
	for _, obj := range tmplObjs {
		result.Templates = append(result.Templates, parseTemplate(obj))
	}
	if e.verbose {
		log.Printf("[+] ADCS: %d template(s)", len(result.Templates))
	}

	e.pace.BetweenRequests()

	// 3. Root CAs
	if e.verbose {
		log.Printf("[*] ADCS: root CAs")
	}
	result.RootCAs, err = e.client.Query(
		"CN=Certification Authorities,"+pkiBase,
		"(objectClass=certificationAuthority)",
		rootCAAttrs,
		adws.ScopeOneLevel,
	)
	if err != nil {
		log.Printf("[*] ADCS: root CAs unavailable")
	}

	e.pace.BetweenRequests()

	// 4. NTAuth store
	if e.verbose {
		log.Printf("[*] ADCS: NTAuth store")
	}
	result.NTAuth, err = e.client.Query(
		"CN=NTAuthCertificates,"+pkiBase,
		"(objectClass=certificationAuthority)",
		rootCAAttrs,
		adws.ScopeBase,
	)
	if err != nil {
		log.Printf("[*] ADCS: NTAuth store unavailable")
	}

	// 5. Client-side ESC analysis
	result.Findings = analyseESC(result)
	if e.verbose {
		log.Printf("[+] ADCS: %d finding(s)", len(result.Findings))
	}

	return result, nil
}

// ── Template parser ───────────────────────────────────────────────────────

func parseTemplate(obj adws.ADObject) TemplateInfo {
	t := TemplateInfo{
		Object:      obj,
		NameFlag:    parseInt(attrStr(obj, "msPKI-Certificate-Name-Flag")),
		EnrollFlag:  parseInt(attrStr(obj, "msPKI-Enrollment-Flag")),
		PrivKeyFlag: parseInt(attrStr(obj, "msPKI-Private-Key-Flag")),
		RASignature: parseInt(attrStr(obj, "msPKI-RA-Signature")),
		EKUs:        attrSlice(obj, "pKIExtendedKeyUsage"),
		AppPolicies: attrSlice(obj, "msPKI-Certificate-Application-Policy"),
	}
	return t
}

// ── ESC analysis (all client-side) ───────────────────────────────────────

func analyseESC(r *ADCSResult) []ESCFinding {
	var findings []ESCFinding

	// Build set of templates published by at least one CA.
	published := map[string]bool{}
	for _, ca := range r.CAs {
		for _, t := range ca.Templates {
			published[t] = true
		}
	}
	// If CA data wasn't available, analyse all templates and note the caveat.
	unknownPublish := len(r.CAs) == 0

	for _, t := range r.Templates {
		name := templateName(t.Object)

		// Only flag templates that are actually published — reduces noise.
		// Skip this check when CA data is unavailable.
		if !unknownPublish && !published[name] {
			continue
		}

		// ── ESC1 ─────────────────────────────────────────────────────
		// ENROLLEE_SUPPLIES_SUBJECT + auth EKU + no RA approval
		if t.NameFlag&ctFlagEnrolleeSuppliesSubject != 0 &&
			t.RASignature == 0 &&
			t.EnrollFlag&ctFlagPendAllRequests == 0 &&
			hasAuthEKU(t.EKUs) {
			f := ESCFinding{
				ESC:         "ESC1",
				Template:    name,
				Risk:        "CRITICAL",
				Description: "Template allows enrollee to supply SAN + has auth EKU + no RA approval. Allows domain privilege escalation by requesting cert as any user.",
				Note:        "Verify enroll/autoenroll rights on template ACL.",
			}
			if unknownPublish {
				f.Note += " (CA data unavailable — publish status unknown)"
			}
			findings = append(findings, f)
		}

		// ── ESC2 ─────────────────────────────────────────────────────
		// Any Purpose EKU or no EKU
		if hasOID(t.EKUs, ekuAnyPurpose) || (len(t.EKUs) == 0 && t.RASignature == 0) {
			findings = append(findings, ESCFinding{
				ESC:         "ESC2",
				Template:    name,
				Risk:        "HIGH",
				Description: "Template has Any Purpose EKU or no EKU. Certificate can be used for any purpose including domain auth.",
				Note:        "Check enrollment rights on template ACL.",
			})
		}

		// ── ESC3 ─────────────────────────────────────────────────────
		// Certificate Request Agent EKU
		if hasOID(t.EKUs, ekuCertReqAgent) && t.RASignature == 0 {
			findings = append(findings, ESCFinding{
				ESC:         "ESC3",
				Template:    name,
				Risk:        "HIGH",
				Description: "Template has Certificate Request Agent EKU. Can be used to enroll on behalf of other users.",
				Note:        "Chain with a template that allows agent enrollment to escalate.",
			})
		}

		// ── ESC9 ─────────────────────────────────────────────────────
		// NO_SECURITY_EXTENSION flag
		if t.EnrollFlag&ctFlagNoSecurityExt != 0 {
			findings = append(findings, ESCFinding{
				ESC:         "ESC9",
				Template:    name,
				Risk:        "HIGH",
				Description: "Template has CT_FLAG_NO_SECURITY_EXTENSION set. szOID_NTDS_CA_SECURITY_EXT is not embedded — certificate mapping relies on UPN/SAN only.",
				Note:        "Exploitable if GenericWrite on any account that lacks altSecurityIdentities protection.",
			})
		}

		// ── ESC15 ────────────────────────────────────────────────────
		// Application policy with auth OID but no standard EKU
		// (EKUwu — bypasses EKU checks via application policies)
		if len(t.EKUs) == 0 && hasAuthEKU(t.AppPolicies) {
			findings = append(findings, ESCFinding{
				ESC:         "ESC15",
				Template:    name,
				Risk:        "HIGH",
				Description: "Template has auth Application Policy but no standard EKU. May bypass EKU validation checks (EKUwu).",
				Note:        "See TrustedSec EKUwu research.",
			})
		}

		// ── ESC4 (ACL-based — flag for manual review) ─────────────────
		// We collect nTSecurityDescriptor but don't parse binary SDs here.
		// Flag templates that are write-accessible as needing ACL review.
		// A proper check requires parsing the raw security descriptor.
		if attrStr(t.Object, "nTSecurityDescriptor") != "" {
			findings = append(findings, ESCFinding{
				ESC:         "ESC4-check",
				Template:    name,
				Risk:        "REVIEW",
				Description: "nTSecurityDescriptor collected. Review ACL for GenericWrite, WriteDACL, WriteOwner, WriteProperty from low-priv principals.",
				Note:        "Parse nTSecurityDescriptor field in output JSON.",
			})
		}
	}

	// ── ESC6 ─────────────────────────────────────────────────────────────
	// EDITF_ATTRIBUTESUBJECTALTNAME2 is a CA-level registry flag — not
	// directly readable via LDAP. Flag all CAs for manual verification.
	for _, ca := range r.CAs {
		caName := attrStr(ca.Object, "cn")
		findings = append(findings, ESCFinding{
			ESC:         "ESC6-check",
			CA:          caName,
			Risk:        "REVIEW",
			Description: "Cannot verify EDITF_ATTRIBUTESUBJECTALTNAME2 via LDAP/ADWS. Manually check CA policy module registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>\\PolicyModules\\...\\EditFlags",
			Note:        "If bit 0x00040 is set, any SAN can be included in cert requests — domain escalation risk.",
		})

		// ── ESC7 (CA ACL — flag for review) ───────────────────────────
		findings = append(findings, ESCFinding{
			ESC:         "ESC7-check",
			CA:          caName,
			Risk:        "REVIEW",
			Description: "Review CA ACL for ManageCertificates/ManageCA rights granted to low-priv principals.",
			Note:        "Parse nTSecurityDescriptor on CA object in output JSON.",
		})
	}

	return findings
}

// ── Helpers ───────────────────────────────────────────────────────────────

func configNC(baseDN string) string {
	return "CN=Configuration," + baseDN
}

func templateName(obj adws.ADObject) string {
	if n := attrStr(obj, "cn"); n != "" {
		return n
	}
	return attrStr(obj, "displayName")
}

func hasAuthEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return false
	}
	for _, eku := range ekus {
		if _, ok := authEKUs[eku]; ok {
			return true
		}
	}
	return false
}

func hasOID(ekus []string, oid string) bool {
	for _, e := range ekus {
		if strings.EqualFold(e, oid) {
			return true
		}
	}
	return false
}

func parseInt(s string) int64 {
	if s == "" {
		return 0
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
