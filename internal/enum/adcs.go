package enum

// adcs.go — Active Directory Certificate Services enumeration via ADWS.
//
// OPSEC strategy vs Certipy:
//   - Certipy sends complex bitmask LDAP filters over port 389 (signatured).
//   - We pull raw template/CA objects via ADWS (port 9389) with simple
//     objectClass filters, then do ALL ESC analysis client-side in Go.
//   - The ADWS query pattern looks identical to a generic config container dump.

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	DomainSID string          `json:"domain_sid,omitempty"`
}

// CAInfo holds an enterprise CA and the names of templates it publishes.
type CAInfo struct {
	Object       adws.ADObject   `json:"object"`
	Templates    []string        `json:"published_templates"`
	WebEndpoints []WebEndpoint   `json:"web_endpoints,omitempty"`
}

// WebEndpoint represents an HTTP enrollment endpoint found on a CA.
type WebEndpoint struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	NTLM       bool   `json:"ntlm"`
	Negotiate  bool   `json:"negotiate"`
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
	ACL         *SDInfo       `json:"acl,omitempty"`
}

// CAACLInfo holds parsed ACL for a CA.
type CAACLInfo struct {
	CA  string  `json:"ca"`
	ACL *SDInfo `json:"acl,omitempty"`
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
	// Try each possible Configuration NC (handles child domains in a forest)
	configCandidates := forestConfigNCs(e.baseDN)
	var configDN, pkiBase string
	var caObjs []adws.ADObject
	var err error

	result := &ADCSResult{}

	// 1. Enterprise CAs (Enrollment Services)
	if e.verbose {
		log.Printf("%s [*] ADCS: enterprise CAs", ts())
	}
	for _, candidate := range configCandidates {
		pki := "CN=Public Key Services,CN=Services," + candidate
		caObjs, err = e.client.QueryWithSDFlags(
			pki,
			"(objectClass=pKIEnrollmentService)",
			caAttrs,
			adws.ScopeSubtree,
			7,
		)
		if err == nil {
			configDN = candidate
			pkiBase = pki
			if e.verbose && candidate != configCandidates[0] {
				log.Printf("%s [*] ADCS: using forest root config NC: %s", ts(), configDN)
			}
			break
		}
	}
	if configDN == "" {
		// All candidates failed — use default and let it fail gracefully
		configDN = configNC(e.baseDN)
		pkiBase = "CN=Public Key Services,CN=Services," + configDN
		log.Printf("%s [*] ADCS: enterprise CAs unavailable", ts())
	}
	for _, obj := range caObjs {
		templates := attrSlice(obj, "certificateTemplates")
		ca := CAInfo{Object: obj, Templates: templates}

		// ESC8: probe web enrollment endpoints
		hostname := attrStr(obj, "dNSHostName")
		if hostname != "" {
			log.Printf("%s [*] ADCS: probing web enrollment on %s", ts(), hostname)
			ca.WebEndpoints = probeWebEnrollment(hostname)
			if len(ca.WebEndpoints) > 0 {
				ntlmCount := 0
				for _, ep := range ca.WebEndpoints {
					if ep.NTLM || ep.Negotiate {
						ntlmCount++
					}
				}
				if ntlmCount > 0 {
					log.Printf("%s [!] ADCS: %d HTTP endpoint(s) with NTLM/Negotiate on %s (ESC8)", ts(), ntlmCount, hostname)
				} else {
					log.Printf("%s [+] ADCS: %d HTTP endpoint(s) on %s (no NTLM)", ts(), len(ca.WebEndpoints), hostname)
				}
			}
		}

		result.CAs = append(result.CAs, ca)
	}
	if e.verbose {
		log.Printf("%s [+] ADCS: %d enterprise CA(s)", ts(), len(result.CAs))
	}

	e.pace.BetweenRequests()

	// 2. Certificate Templates
	if e.verbose {
		log.Printf("%s [*] ADCS: certificate templates", ts())
	}
	tmplObjs, err := e.client.QueryWithSDFlags(
		pkiBase,
		"(objectClass=pKIcertificateTemplate)",
		templateAttrs,
		adws.ScopeSubtree,
		7, // OWNER + GROUP + DACL
	)
	if err != nil {
		return nil, fmt.Errorf("adcs templates: %w", err)
	}
	for _, obj := range tmplObjs {
		result.Templates = append(result.Templates, parseTemplate(obj))
	}
	if e.verbose {
		log.Printf("%s [+] ADCS: %d template(s)", ts(), len(result.Templates))
	}

	e.pace.BetweenRequests()

	// 3. Root CAs
	if e.verbose {
		log.Printf("%s [*] ADCS: root CAs", ts())
	}
	result.RootCAs, err = e.client.Query(
		"CN=Certification Authorities,"+pkiBase,
		"(objectClass=certificationAuthority)",
		rootCAAttrs,
		adws.ScopeOneLevel,
	)
	if err != nil {
		log.Printf("%s [*] ADCS: root CAs unavailable", ts())
	}

	e.pace.BetweenRequests()

	// 4. NTAuth store
	if e.verbose {
		log.Printf("%s [*] ADCS: NTAuth store", ts())
	}
	result.NTAuth, err = e.client.Query(
		"CN=NTAuthCertificates,"+pkiBase,
		"(objectClass=certificationAuthority)",
		rootCAAttrs,
		adws.ScopeBase,
	)
	if err != nil {
		log.Printf("%s [*] ADCS: NTAuth store unavailable", ts())
	}

	// Check if SDs were returned and derive domain SID from owner
	sdCount := 0
	domainSID := ""
	for _, t := range result.Templates {
		if t.ACL != nil {
			sdCount++
			// Derive domain SID from owner SID (strip last RID)
			if domainSID == "" && t.ACL.OwnerSID != "" {
				owner := t.ACL.OwnerSID
				idx := strings.LastIndex(owner, "-")
				if idx > 0 && strings.HasPrefix(owner, "S-1-5-21-") {
					domainSID = owner[:idx]
				}
			}
		}
	}
	result.DomainSID = domainSID
	if sdCount > 0 {
		log.Printf("%s [+] ADCS: parsed ACLs on %d/%d templates", ts(), sdCount, len(result.Templates))
	} else if len(result.Templates) > 0 {
		log.Printf("%s [*] ADCS: nTSecurityDescriptor not readable (need privileged account for enrollment ACLs)", ts())
	}

	// 5. Client-side ESC analysis
	result.Findings = analyseESC(result, domainSID)
	if e.verbose {
		log.Printf("%s [+] ADCS: %d finding(s)", ts(), len(result.Findings))
	}

	return result, nil
}

// ── Template parser ───────────────────────────────────────────────────────

// isLowPrivSID returns true for SIDs that represent low-privilege principals
// (Everyone, Authenticated Users, Domain Users, Domain Computers).
func isLowPrivSID(sid string) bool {
	lowPriv := map[string]bool{
		"S-1-1-0":  true, // Everyone
		"S-1-5-7":  true, // Anonymous
		"S-1-5-11": true, // Authenticated Users
	}
	if lowPriv[sid] {
		return true
	}
	// Domain Users (RID 513), Domain Computers (RID 515)
	if strings.HasSuffix(sid, "-513") || strings.HasSuffix(sid, "-515") {
		return true
	}
	return false
}

// enrollersDescription returns a human-readable list of who can enroll.
func enrollersDescription(acl *SDInfo, domainSID string) string {
	if acl == nil {
		return ""
	}
	var parts []string
	seen := map[string]bool{}
	for _, ace := range acl.Enrollers {
		name := FriendlySID(ace.SID, domainSID)
		if !seen[name] {
			parts = append(parts, fmt.Sprintf("%s (%s)", name, ace.Rights))
			seen[name] = true
		}
	}
	for _, ace := range acl.FullControl {
		name := FriendlySID(ace.SID, domainSID)
		if !seen[name] {
			parts = append(parts, fmt.Sprintf("%s (GenericAll)", name))
			seen[name] = true
		}
	}
	if len(parts) == 0 {
		return ""
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

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
	// Parse ACL from nTSecurityDescriptor
	sdRaw := attrStr(obj, "nTSecurityDescriptor")
	if sdRaw != "" {
		t.ACL = ParseSD(sdRaw)
	}
	return t
}

// ── ESC analysis (all client-side) ───────────────────────────────────────

func analyseESC(r *ADCSResult, domainSID string) []ESCFinding {
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
			enrollDesc := enrollersDescription(t.ACL, domainSID)
			desc := "Template allows enrollee to supply SAN + has auth EKU + no RA approval. Allows domain privilege escalation by requesting cert as any user."
			if enrollDesc != "" {
				desc += "\n    Enrollers: " + enrollDesc
			}
			f := ESCFinding{
				ESC:         "ESC1",
				Template:    name,
				Risk:        "CRITICAL",
				Description: desc,
				Note:        "",
			}
			if unknownPublish {
				f.Note = "(CA data unavailable — publish status unknown)"
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

		// ── ESC4 (ACL-based — writable templates) ──────────────────
		if t.ACL != nil {
			// Check for dangerous write ACEs from non-admin principals
			for _, ace := range t.ACL.Writers {
				if isLowPrivSID(ace.SID) {
					findings = append(findings, ESCFinding{
						ESC:         "ESC4",
						Template:    name,
						Risk:        "HIGH",
						Description: fmt.Sprintf("Template writable by %s (%s). Can modify template to enable ESC1.", ace.SID, ace.Rights),
						Note:        "Modify template flags to allow SAN + auth EKU, then enroll.",
					})
					break // one finding per template
				}
			}
			for _, ace := range t.ACL.FullControl {
				if isLowPrivSID(ace.SID) {
					findings = append(findings, ESCFinding{
						ESC:         "ESC4",
						Template:    name,
						Risk:        "CRITICAL",
						Description: fmt.Sprintf("Template GenericAll by %s. Full control over template.", ace.SID),
						Note:        "Modify template for ESC1, then enroll as any user.",
					})
					break
				}
			}
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

		// ── ESC7 (CA ACL — ManageCertificates/ManageCA) ──────────────
		caSDRaw := attrStr(ca.Object, "nTSecurityDescriptor")
		if caSDRaw != "" {
			caSD := ParseSD(caSDRaw)
			if caSD != nil {
				for _, ace := range caSD.Writers {
					if isLowPrivSID(ace.SID) {
						findings = append(findings, ESCFinding{
							ESC:         "ESC7",
							CA:          caName,
							Risk:        "HIGH",
							Description: fmt.Sprintf("CA writable by %s (%s). May have ManageCertificates/ManageCA.", ace.SID, ace.Rights),
							Note:        "ManageCA can modify CA config. ManageCertificates can approve pending requests.",
						})
						break
					}
				}
				for _, ace := range caSD.FullControl {
					if isLowPrivSID(ace.SID) {
						findings = append(findings, ESCFinding{
							ESC:         "ESC7",
							CA:          caName,
							Risk:        "CRITICAL",
							Description: fmt.Sprintf("CA GenericAll by %s. Full control over CA.", ace.SID),
							Note:        "Can modify CA configuration and approve certificate requests.",
						})
						break
					}
				}
			}
		} else {
			findings = append(findings, ESCFinding{
				ESC:         "ESC7-check",
				CA:          caName,
				Risk:        "REVIEW",
				Description: "CA nTSecurityDescriptor not readable. Manually review CA ACL.",
				Note:        "Check ManageCertificates/ManageCA rights.",
			})
		}
	}

	// ── ESC8 (HTTP enrollment with NTLM — relay target) ─────────────
	for _, ca := range r.CAs {
		caName := attrStr(ca.Object, "cn")
		for _, ep := range ca.WebEndpoints {
			if ep.NTLM || ep.Negotiate {
				authType := "NTLM"
				if ep.Negotiate && !ep.NTLM {
					authType = "Negotiate (NTLM fallback)"
				} else if ep.Negotiate && ep.NTLM {
					authType = "NTLM + Negotiate"
				}
				findings = append(findings, ESCFinding{
					ESC:         "ESC8",
					CA:          caName,
					Risk:        "CRITICAL",
					Description: fmt.Sprintf("CA exposes HTTP enrollment at %s with %s auth. Relay NTLM authentication to request certificates as the relayed user.", ep.URL, authType),
					Note:        "Use ntlmrelayx.py --target " + ep.URL + " --adcs --template <template>",
				})
			}
		}
	}

	return findings
}

// ── ESC8: HTTP enrollment endpoint probe ─────────────────────────────────

// probeWebEnrollment checks if a CA exposes HTTP-based enrollment endpoints
// that accept NTLM authentication (ESC8 relay target).
func probeWebEnrollment(hostname string) []WebEndpoint {
	if hostname == "" {
		return nil
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	endpoints := []string{
		"/certsrv/",
		"/certsrv/certfnsh.asp",
		"/ADPolicyProvider_CEP_Usernamepassword/service.svc",
		"/CES_Kerberos/service.svc",
	}

	var results []WebEndpoint
	for _, scheme := range []string{"http", "https"} {
		for _, ep := range endpoints {
			url := fmt.Sprintf("%s://%s%s", scheme, hostname, ep)
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			resp.Body.Close()

			we := WebEndpoint{
				URL:    url,
				Status: resp.StatusCode,
			}

			// Check WWW-Authenticate header for NTLM/Negotiate
			authHeader := resp.Header.Get("WWW-Authenticate")
			if authHeader == "" && resp.StatusCode == 401 {
				// Some servers only return auth header on 401
				we.NTLM = false
			}
			if strings.Contains(authHeader, "NTLM") {
				we.NTLM = true
			}
			if strings.Contains(authHeader, "Negotiate") {
				we.Negotiate = true
			}

			// Interesting if reachable (200, 401, 403)
			if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
				results = append(results, we)
			}
		}
	}

	return results
}

// ── Helpers ───────────────────────────────────────────────────────────────

func configNC(baseDN string) string {
	return "CN=Configuration," + baseDN
}

// forestConfigNCs returns possible Configuration NC DNs for a domain,
// trying the full domain first, then progressively stripping child DCs
// to find the forest root. For amer.corp.local → tries:
//   CN=Configuration,DC=Amer,DC=Corp,DC=Local
//   CN=Configuration,DC=Corp,DC=Local
//   CN=Configuration,DC=Local
func forestConfigNCs(baseDN string) []string {
	results := []string{configNC(baseDN)}
	parts := strings.Split(baseDN, ",")
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ",")
		results = append(results, "CN=Configuration,"+candidate)
	}
	return results
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
