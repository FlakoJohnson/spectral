package output

// bloodhound.go — converts collected AD objects to BloodHound CE v5 JSON format.
//
// BH CE expects one file per object type, each with:
//   { "data": [...], "meta": { "methods": N, "type": "users", "count": N, "version": 5 } }
//
// All files are zipped into a single archive for drag-and-drop import.

import (
	"archive/zip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sopa "github.com/Macmod/sopa"

	"spectral/internal/adws"
	"spectral/internal/enum"
)

// BH CE collection method bitmask values (from SharpHound source).
const (
	bhMethodGroup      = 0x0001
	bhMethodObjectProp = 0x0100
	bhMethodTrusts     = 0x0010
	bhMethodACL        = 0x0020

	bhVersion = 6
)

// ── Top-level BH file wrapper ─────────────────────────────────────────────

type bhFile struct {
	Data interface{} `json:"data"`
	Meta bhMeta      `json:"meta"`
}

type bhMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

// ── BH object types ───────────────────────────────────────────────────────

type bhUser struct {
	ObjectIdentifier  string        `json:"ObjectIdentifier"`
	Properties        bhUserProps   `json:"Properties"`
	AllowedToDelegate []bhTypedID   `json:"AllowedToDelegate"`
	PrimaryGroupSID   string        `json:"PrimaryGroupSID"`
	HasSIDHistory     []bhTypedID   `json:"HasSIDHistory"`
	SPNTargets        []bhSPNTarget `json:"SPNTargets"`
	Aces              []bhAce       `json:"Aces"`
	IsDeleted         bool          `json:"IsDeleted"`
	IsACLProtected    bool          `json:"IsACLProtected"`
	DomainSID         string        `json:"DomainSID"`
	UnconstrainedDelegation bool    `json:"UnconstrainedDelegation"`
}

type bhUserProps struct {
	Name                  string   `json:"name"`
	Domain                string   `json:"domain"`
	DomainSID             string   `json:"domainsid"`
	DistinguishedName     string   `json:"distinguishedname"`
	SAMAccountName        string   `json:"samaccountname"`
	DisplayName           string   `json:"displayname"`
	Description           string   `json:"description"`
	Email                 string   `json:"email"`
	Enabled               bool     `json:"enabled"`
	AdminCount            bool     `json:"admincount"`
	HasSPN                bool     `json:"hasspn"`
	DontReqPreauth        bool     `json:"dontreqpreauth"`
	UnconstrainedDelegate bool     `json:"unconstraineddelegation"`
	PwdNeverExpires       bool     `json:"pwdneverexpires"`
	SensitiveAccount      bool     `json:"sensitive"`
	TrustedToAuth         bool     `json:"trustedtoauth"`
	SPNs                  []string `json:"serviceprincipalnames"`
	LastLogon             int64    `json:"lastlogon"`
	LastLogonTimestamp    int64    `json:"lastlogontimestamp"`
	PwdLastSet            int64    `json:"pwdlastset"`
	WhenCreated           int64    `json:"whencreated"`
	HighValue             bool     `json:"highvalue"`
}

type bhComputer struct {
	ObjectIdentifier  string             `json:"ObjectIdentifier"`
	Properties        bhComputerProps    `json:"Properties"`
	PrimaryGroupSID   string             `json:"PrimaryGroupSID"`
	AllowedToDelegate []bhTypedID        `json:"AllowedToDelegate"`
	AllowedToAct      []bhTypedID        `json:"AllowedToAct"`
	DumpSMSAPassword  []bhTypedID        `json:"DumpSMSAPassword"`
	HasSIDHistory     []bhTypedID        `json:"HasSIDHistory"`
	Sessions          bhSessionResult    `json:"Sessions"`
	PrivilegedSessions bhSessionResult   `json:"PrivilegedSessions"`
	RegistrySessions  bhSessionResult    `json:"RegistrySessions"`
	LocalGroups       []bhLocalGroupResult `json:"LocalGroups"`
	UserRights        []bhUserRightResult  `json:"UserRights"`
	DCRegistryData    bhDCRegistryData   `json:"DCRegistryData"`
	Status            bhConnStatus       `json:"Status"`
	Aces              []bhAce            `json:"Aces"`
	IsDeleted         bool               `json:"IsDeleted"`
	IsACLProtected    bool               `json:"IsACLProtected"`
	IsDC              bool               `json:"IsDC"`
	DomainSID         string             `json:"DomainSID"`
	UnconstrainedDelegation bool         `json:"UnconstrainedDelegation"`
}

type bhComputerProps struct {
	Name                  string   `json:"name"`
	Domain                string   `json:"domain"`
	DomainSID             string   `json:"domainsid"`
	DistinguishedName     string   `json:"distinguishedname"`
	SAMAccountName        string   `json:"samaccountname"`
	DNSHostName           string   `json:"dnshostname"`
	OperatingSystem       string   `json:"operatingsystem"`
	Enabled               bool     `json:"enabled"`
	UnconstrainedDelegate bool     `json:"unconstraineddelegation"`
	TrustedToAuth         bool     `json:"trustedtoauth"`
	HasSPN                bool     `json:"hasspn"`
	SPNs                  []string `json:"serviceprincipalnames"`
	LastLogon             int64    `json:"lastlogon"`
	LastLogonTimestamp    int64    `json:"lastlogontimestamp"`
	WhenCreated           int64    `json:"whencreated"`
	HighValue             bool     `json:"highvalue"`
}

type bhGroup struct {
	ObjectIdentifier string       `json:"ObjectIdentifier"`
	Properties       bhGroupProps `json:"Properties"`
	Members          []bhTypedID  `json:"Members"`
	Aces             []bhAce      `json:"Aces"`
	IsDeleted        bool         `json:"IsDeleted"`
	IsACLProtected   bool         `json:"IsACLProtected"`
}

type bhGroupProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	SAMAccountName    string `json:"samaccountname"`
	Description       string `json:"description"`
	AdminCount        bool   `json:"admincount"`
	WhenCreated       int64  `json:"whencreated"`
	HighValue         bool   `json:"highvalue"`
}

type bhGPO struct {
	ObjectIdentifier string    `json:"ObjectIdentifier"`
	Properties       bhGPOProps `json:"Properties"`
	Aces             []bhAce   `json:"Aces"`
	IsDeleted        bool      `json:"IsDeleted"`
	IsACLProtected   bool      `json:"IsACLProtected"`
}

type bhGPOProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	GPCPath           string `json:"gpcpath"`
	WhenCreated       int64  `json:"whencreated"`
	HighValue         bool   `json:"highvalue"`
}

type bhDomain struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	Properties       bhDomainProps `json:"Properties"`
	Trusts           []bhTrust     `json:"Trusts"`
	Aces             []bhAce       `json:"Aces"`
	ChildObjects     []bhTypedID   `json:"ChildObjects"`
	Links            []bhGPOLink   `json:"Links"`
	IsDeleted        bool          `json:"IsDeleted"`
	IsACLProtected   bool          `json:"IsACLProtected"`
}

type bhDomainProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	FunctionalLevel   string `json:"functionallevel"`
	Collected         bool   `json:"collected"`
	HighValue         bool   `json:"highvalue"`
	WhenCreated       int64  `json:"whencreated"`
}

// Shared helper types.
type bhTypedID struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type bhAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

type bhTrust struct {
	TargetDomainSid     string `json:"TargetDomainSid"`
	TargetDomainName    string `json:"TargetDomainName"`
	IsTransitive        bool   `json:"IsTransitive"`
	TrustDirection      string `json:"TrustDirection"`
	TrustType           string `json:"TrustType"`
	SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
	TGTDelegationEnabled bool  `json:"TGTDelegationEnabled"`
}

type bhGPOLink struct {
	GUID       string `json:"GUID"`
	IsEnforced bool   `json:"IsEnforced"`
}

type bhSPNTarget struct {
	ComputerSID string `json:"ComputerSID"`
	Port        int    `json:"Port"`
	Service     string `json:"Service"`
}

type bhSessionResult struct {
	Results   []bhSession `json:"Results"`
	Collected bool        `json:"Collected"`
}

type bhSession struct {
	ComputerSID string `json:"ComputerSID"`
	UserSID     string `json:"UserSID"`
	LogonType   int    `json:"LogonType"`
}

type bhLocalGroupResult struct {
	Results          []bhTypedID `json:"Results"`
	Name             string     `json:"Name"`
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Collected        bool       `json:"Collected"`
}

type bhUserRightResult struct {
	Results   []bhTypedID `json:"Results"`
	Privilege string      `json:"Privilege"`
	Collected bool        `json:"Collected"`
}

type bhDCRegistryData struct {
	CertificateMappingMethods bhRegResult `json:"CertificateMappingMethods"`
	StrongCertificateBindingEnforcement bhRegResult `json:"StrongCertificateBindingEnforcement"`
}

type bhRegResult struct {
	Collected bool `json:"Collected"`
	Value     int  `json:"Value"`
}

type bhConnStatus struct {
	Connectable bool   `json:"Connectable"`
	Error       string `json:"Error"`
}

// ── Main converter ────────────────────────────────────────────────────────

// BHConverter holds collected data and converts it to BH CE format.
type BHConverter struct {
	domain    string
	domainSID string
	// DN → SID lookup built from users + computers for member resolution.
	dnToSID  map[string]string
	dnToType map[string]string
}

// NewBHConverter creates a converter. domainSID is the domain's S-1-5-21-... SID.
func NewBHConverter(domain, domainSID string) *BHConverter {
	return &BHConverter{
		domain:    strings.ToUpper(domain),
		domainSID: domainSID,
		dnToSID:   make(map[string]string),
		dnToType:  make(map[string]string),
	}
}

// IndexObjects builds the DN→SID/type lookup from users, computers, and groups.
// Call this before ConvertGroups so member SIDs can be resolved.
func (c *BHConverter) IndexObjects(users, computers, groups []adws.ADObject) {
	for _, u := range users {
		dn := enum.AttrStr(u, "distinguishedName")
		sid := enum.SIDStr(u, "objectSid")
		if dn != "" && sid != "" {
			c.dnToSID[strings.ToUpper(dn)] = sid
			c.dnToType[strings.ToUpper(dn)] = "User"
		}
	}
	for _, comp := range computers {
		dn := enum.AttrStr(comp, "distinguishedName")
		sid := enum.SIDStr(comp, "objectSid")
		if dn != "" && sid != "" {
			c.dnToSID[strings.ToUpper(dn)] = sid
			c.dnToType[strings.ToUpper(dn)] = "Computer"
		}
	}
	for _, g := range groups {
		dn := enum.AttrStr(g, "distinguishedName")
		sid := enum.SIDStr(g, "objectSid")
		if dn != "" && sid != "" {
			c.dnToSID[strings.ToUpper(dn)] = sid
			c.dnToType[strings.ToUpper(dn)] = "Group"
		}
	}
}

// ── Object converters ─────────────────────────────────────────────────────

func (c *BHConverter) ConvertUsers(objects []adws.ADObject) []bhUser {
	out := make([]bhUser, 0, len(objects))
	for _, obj := range objects {
		sid := enum.SIDStr(obj, "objectSid")
		if sid == "" {
			continue
		}
		uac := parseInt64(enum.AttrStr(obj, "userAccountControl"))
		sam := enum.AttrStr(obj, "sAMAccountName")

		// Build PrimaryGroupSID: domainSID + "-" + primaryGroupID
		pgid := enum.AttrStr(obj, "primaryGroupID")
		primaryGroupSID := ""
		if pgid != "" && c.domainSID != "" {
			primaryGroupSID = c.domainSID + "-" + pgid
		}

		u := bhUser{
			ObjectIdentifier:       sid,
			PrimaryGroupSID:        primaryGroupSID,
			AllowedToDelegate:      []bhTypedID{},
			HasSIDHistory:          []bhTypedID{},
			SPNTargets:             []bhSPNTarget{},
			Aces:                   sdToBHAces(obj, c.dnToSID, c.dnToType),
			DomainSID:              c.domainSID,
			UnconstrainedDelegation: uac&0x80000 != 0,
			Properties: bhUserProps{
				Name:                  fmt.Sprintf("%s@%s", strings.ToUpper(sam), c.domain),
				Domain:                c.domain,
				DomainSID:             c.domainSID,
				DistinguishedName:     strings.ToUpper(enum.AttrStr(obj, "distinguishedName")),
				SAMAccountName:        sam,
				DisplayName:           enum.AttrStr(obj, "displayName"),
				Description:           enum.AttrStr(obj, "description"),
				Email:                 enum.AttrStr(obj, "mail"),
				Enabled:               uac&0x2 == 0,
				AdminCount:            parseInt64(enum.AttrStr(obj, "adminCount")) == 1,
				SPNs:                  enum.AttrSliceStr(obj, "servicePrincipalName"),
				HasSPN:                len(enum.AttrSliceStr(obj, "servicePrincipalName")) > 0,
				DontReqPreauth:        uac&0x400000 != 0,
				UnconstrainedDelegate: uac&0x80000 != 0,
				TrustedToAuth:         uac&0x1000000 != 0,
				PwdNeverExpires:       uac&0x10000 != 0,
				LastLogon:             fileTimeToUnix(enum.AttrStr(obj, "lastLogon")),
				LastLogonTimestamp:    fileTimeToUnix(enum.AttrStr(obj, "lastLogonTimestamp")),
				PwdLastSet:            fileTimeToUnix(enum.AttrStr(obj, "pwdLastSet")),
				WhenCreated:           parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
			},
		}
		out = append(out, u)
	}
	return out
}

func (c *BHConverter) ConvertComputers(objects []adws.ADObject) []bhComputer {
	out := make([]bhComputer, 0, len(objects))
	for _, obj := range objects {
		sid := enum.SIDStr(obj, "objectSid")
		if sid == "" {
			continue
		}
		uac := parseInt64(enum.AttrStr(obj, "userAccountControl"))
		sam := enum.AttrStr(obj, "sAMAccountName")
		dns := enum.AttrStr(obj, "dNSHostName")

		name := dns
		if name == "" {
			name = strings.TrimSuffix(strings.ToUpper(sam), "$")
		}

		pgid := enum.AttrStr(obj, "primaryGroupID")
		compPGSID := ""
		if pgid != "" && c.domainSID != "" {
			compPGSID = c.domainSID + "-" + pgid
		}

		isDC := uac&0x2000 != 0 // SERVER_TRUST_ACCOUNT

		comp := bhComputer{
			ObjectIdentifier:       sid,
			PrimaryGroupSID:        compPGSID,
			AllowedToDelegate:      []bhTypedID{},
			AllowedToAct:           []bhTypedID{},
			DumpSMSAPassword:       []bhTypedID{},
			HasSIDHistory:          []bhTypedID{},
			Sessions:               bhSessionResult{Results: []bhSession{}, Collected: false},
			PrivilegedSessions:     bhSessionResult{Results: []bhSession{}, Collected: false},
			RegistrySessions:       bhSessionResult{Results: []bhSession{}, Collected: false},
			LocalGroups:            []bhLocalGroupResult{},
			UserRights:             []bhUserRightResult{},
			DCRegistryData:         bhDCRegistryData{},
			Status:                 bhConnStatus{Connectable: false, Error: ""},
			Aces:                   sdToBHAces(obj, c.dnToSID, c.dnToType),
			IsDC:                   isDC,
			DomainSID:              c.domainSID,
			UnconstrainedDelegation: uac&0x80000 != 0,
			Properties: bhComputerProps{
				Name:                  fmt.Sprintf("%s@%s", strings.ToUpper(name), c.domain),
				Domain:                c.domain,
				DomainSID:             c.domainSID,
				DistinguishedName:     strings.ToUpper(enum.AttrStr(obj, "distinguishedName")),
				SAMAccountName:        sam,
				DNSHostName:           dns,
				OperatingSystem:       enum.AttrStr(obj, "operatingSystem"),
				Enabled:               uac&0x2 == 0,
				UnconstrainedDelegate: uac&0x80000 != 0,
				TrustedToAuth:         uac&0x1000000 != 0,
				SPNs:                  enum.AttrSliceStr(obj, "servicePrincipalName"),
				HasSPN:                len(enum.AttrSliceStr(obj, "servicePrincipalName")) > 0,
				LastLogon:             fileTimeToUnix(enum.AttrStr(obj, "lastLogon")),
				LastLogonTimestamp:    fileTimeToUnix(enum.AttrStr(obj, "lastLogonTimestamp")),
				WhenCreated:           parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
			},
		}
		out = append(out, comp)
	}
	return out
}

func (c *BHConverter) ConvertGroups(objects []adws.ADObject) []bhGroup {
	out := make([]bhGroup, 0, len(objects))
	for _, obj := range objects {
		sid := enum.SIDStr(obj, "objectSid")
		if sid == "" {
			continue
		}
		sam := enum.AttrStr(obj, "sAMAccountName")

		// Resolve member DNs to SID+type pairs.
		memberDNs := enum.AttrSliceStr(obj, "member")
		members := make([]bhTypedID, 0, len(memberDNs))
		for _, dn := range memberDNs {
			upper := strings.ToUpper(dn)
			if msid, ok := c.dnToSID[upper]; ok {
				members = append(members, bhTypedID{
					ObjectIdentifier: msid,
					ObjectType:       c.dnToType[upper],
				})
			} else if fspSID := extractFSPSID(dn); fspSID != "" {
				// ForeignSecurityPrincipal — CN contains the SID
				members = append(members, bhTypedID{
					ObjectIdentifier: fspSID,
					ObjectType:       "Group",
				})
			} else {
				// Unresolved DN — send raw DN so BH can resolve if object exists in graph
				members = append(members, bhTypedID{
					ObjectIdentifier: dn,
					ObjectType:       "Base",
				})
			}
		}

		g := bhGroup{
			ObjectIdentifier: sid,
			Members:          members,
			Aces:             sdToBHAces(obj, c.dnToSID, c.dnToType),
			Properties: bhGroupProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(sam), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(enum.AttrStr(obj, "distinguishedName")),
				SAMAccountName:    sam,
				Description:       enum.AttrStr(obj, "description"),
				AdminCount:        parseInt64(enum.AttrStr(obj, "adminCount")) == 1,
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
			},
		}
		out = append(out, g)
	}
	return out
}

func (c *BHConverter) ConvertGPOs(objects []adws.ADObject) []bhGPO {
	out := make([]bhGPO, 0, len(objects))
	for _, obj := range objects {
		guid := convertGUID(enum.AttrStr(obj, "objectGUID"))
		if guid == "" {
			continue
		}
		name := enum.AttrStr(obj, "displayName")

		gpo := bhGPO{
			ObjectIdentifier: guid,
			Aces:             []bhAce{},
			Properties: bhGPOProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(name), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(enum.AttrStr(obj, "distinguishedName")),
				GPCPath:           enum.AttrStr(obj, "gPCFileSysPath"),
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
			},
		}
		out = append(out, gpo)
	}
	return out
}

func (c *BHConverter) ConvertTrusts(objects []adws.ADObject) []bhTrust {
	out := make([]bhTrust, 0, len(objects))
	for _, obj := range objects {
		name := enum.AttrStr(obj, "name")
		direction := parseInt64(enum.AttrStr(obj, "trustDirection"))
		ttype := parseInt64(enum.AttrStr(obj, "trustType"))
		attrs := parseInt64(enum.AttrStr(obj, "trustAttributes"))

		targetSID := enum.SIDStr(obj, "securityIdentifier")

		trust := bhTrust{
			TargetDomainSid:      targetSID,
			TargetDomainName:     strings.ToUpper(name),
			TrustDirection:       trustDirectionStr(direction),
			TrustType:            trustTypeStr(ttype),
			IsTransitive:         attrs&0x8 != 0,
			SidFilteringEnabled:  attrs&0x4 != 0,
			TGTDelegationEnabled: attrs&0x20 != 0,
		}
		out = append(out, trust)
	}
	return out
}

// ── ZIP writer ─────────────────────────────────────────────────────────────

// WriteBHZip serialises all collected data as BH CE JSON files inside a zip.
func WriteBHZip(
	outDir, filePrefix, domain, domainSID string,
	users, computers, groups, gpos, trusts []adws.ADObject,
	domainInfo *enum.DomainResult,
) error {
	c := NewBHConverter(domain, domainSID)
	c.IndexObjects(users, computers, groups)

	zipPath := filepath.Join(outDir, fmt.Sprintf("%s_bloodhound.zip", filePrefix))
	f, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	type entry struct {
		name    string
		objType string
		methods int
		data    interface{}
		count   int
	}

	bhUsers := c.ConvertUsers(users)
	bhComps := c.ConvertComputers(computers)
	bhGroups := c.ConvertGroups(groups)
	bhGPOs := c.ConvertGPOs(gpos)
	bhTrustsSlice := c.ConvertTrusts(trusts)


	// Build distinguished name from domain FQDN: corp.local → DC=CORP,DC=LOCAL
	dnParts := strings.Split(strings.ToUpper(domain), ".")
	dnComponents := make([]string, len(dnParts))
	for i, p := range dnParts {
		dnComponents[i] = "DC=" + p
	}
	domainDN := strings.Join(dnComponents, ",")

	// Build domain properties — use ADCAP data if available
	funcLevel := "Unknown"
	if domainInfo != nil {
		if d, ok := domainInfo.Domain.(*sopa.ADCAPActiveDirectoryDomain); ok && d != nil {
			funcLevel = domainModeStr(d.DomainMode)
			if domainSID == "" && d.DomainSID != "" {
				// ADCAP returns SID as base64 binary — try to convert
				if strings.HasPrefix(d.DomainSID, "S-1-") {
					domainSID = d.DomainSID
				} else {
					// Try base64 decode → SID conversion
					raw, err := base64.StdEncoding.DecodeString(d.DomainSID)
					if err == nil && len(raw) >= 8 {
						domainSID = adws.ConvertSID(raw)
					}
					if domainSID == "" {
						domainSID = d.DomainSID // fallback to raw
					}
				}
			}
		}
	}

	domainObj := bhDomain{
		ObjectIdentifier: domainSID,
		Properties: bhDomainProps{
			Name:              strings.ToUpper(domain),
			Domain:            strings.ToUpper(domain),
			DomainSID:         domainSID,
			DistinguishedName: domainDN,
			FunctionalLevel:   funcLevel,
			Collected:         true,
			HighValue:         true,
			WhenCreated:       -1,
		},
		Trusts:       bhTrustsSlice,
		Aces:         []bhAce{},
		ChildObjects: []bhTypedID{},
		Links:        []bhGPOLink{},
	}

	entries := []entry{
		{"users.json", "users", bhMethodObjectProp | bhMethodACL, bhUsers, len(bhUsers)},
		{"computers.json", "computers", bhMethodObjectProp | bhMethodACL, bhComps, len(bhComps)},
		{"groups.json", "groups", bhMethodGroup | bhMethodObjectProp | bhMethodACL, bhGroups, len(bhGroups)},
		{"gpos.json", "gpos", bhMethodObjectProp | bhMethodACL, bhGPOs, len(bhGPOs)},
		{"domains.json", "domains", bhMethodObjectProp | bhMethodTrusts | bhMethodACL, []bhDomain{domainObj}, 1},
	}

	for _, e := range entries {
		payload := bhFile{
			Data: e.data,
			Meta: bhMeta{Methods: e.methods, Type: e.objType, Count: e.count, Version: bhVersion},
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", e.name, err)
		}
		w, err := zw.Create(e.name)
		if err != nil {
			return fmt.Errorf("zip %s: %w", e.name, err)
		}
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("write %s: %w", e.name, err)
		}
	}

	fmt.Printf("  %s[+]%s BloodHound zip: %s\n", green+bold, reset, zipPath)
	return nil
}

// ── Conversion helpers ────────────────────────────────────────────────────

// convertGUID decodes a base64 objectGUID and formats it as {xxxxxxxx-xxxx-...}.
// Windows stores GUIDs in mixed-endian: first 3 components are little-endian.
// sdToBHAces converts parsed nTSecurityDescriptor ACEs to BloodHound ACE format.
func sdToBHAces(obj adws.ADObject, dnToSID map[string]string, dnToType map[string]string) []bhAce {
	sdRaw := enum.AttrStr(obj, "nTSecurityDescriptor")
	if sdRaw == "" {
		return []bhAce{}
	}
	sd := enum.ParseSD(sdRaw)
	if sd == nil {
		return []bhAce{}
	}

	var aces []bhAce

	// Map access mask bits to BH right names
	type aceMapping struct {
		mask  uint32
		right string
		guid  string // for object-specific ACEs
	}

	for _, sdAce := range append(append(sd.Enrollers, sd.Writers...), sd.FullControl...) {
		if sdAce.Type != "Allow" {
			continue
		}

		principalSID := sdAce.SID
		principalType := "Base" // default

		// Try to determine principal type from our index
		for dn, sid := range dnToSID {
			if sid == principalSID {
				if t, ok := dnToType[dn]; ok {
					principalType = t
				}
				break
			}
		}

		// Well-known SID types
		switch {
		case strings.HasSuffix(principalSID, "-513"), strings.HasSuffix(principalSID, "-512"),
			strings.HasSuffix(principalSID, "-519"), strings.HasSuffix(principalSID, "-518"):
			principalType = "Group"
		case principalSID == "S-1-5-11", principalSID == "S-1-1-0", principalSID == "S-1-5-32-544",
			principalSID == "S-1-5-32-545":
			principalType = "Group"
		case principalSID == "S-1-5-18":
			principalType = "User"
		}

		mask := sdAce.AccessMask

		if mask&0x10000000 != 0 { // GenericAll
			aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GenericAll", IsInherited: false})
			continue
		}
		if mask&0x40000000 != 0 { // GenericWrite
			aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GenericWrite", IsInherited: false})
		}
		if mask&0x00040000 != 0 { // WriteDACL
			aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "WriteDacl", IsInherited: false})
		}
		if mask&0x00080000 != 0 { // WriteOwner
			aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "WriteOwner", IsInherited: false})
		}
		if mask&0x00000100 != 0 { // Extended rights
			if sdAce.ObjectGUID == "" {
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "AllExtendedRights", IsInherited: false})
			} else if sdAce.ObjectGUID == "00299570-246d-11d0-a768-00aa006e0529" {
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "ForceChangePassword", IsInherited: false})
			}
		}
		if mask&0x00000020 != 0 { // WriteProperty
			if sdAce.ObjectGUID == "bf9679c0-0de6-11d0-a285-00aa003049e2" {
				// member attribute
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "AddMember", IsInherited: false})
			}
		}
		if mask&0x00000100 != 0 && sdAce.ObjectGUID == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" {
			aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GetChanges", IsInherited: false})
		}
		if mask&0x00000100 != 0 && sdAce.ObjectGUID == "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" {
			aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GetChangesAll", IsInherited: false})
		}
	}

	// Owner gets Owns edge
	if sd.OwnerSID != "" {
		aces = append(aces, bhAce{PrincipalSID: sd.OwnerSID, PrincipalType: "Base", RightName: "Owns", IsInherited: false})
	}

	return aces
}

func domainModeStr(mode int) string {
	switch mode {
	case 0:
		return "Windows 2000"
	case 1:
		return "Windows Server 2003 Mixed"
	case 2:
		return "Windows Server 2003"
	case 3:
		return "Windows Server 2008"
	case 4:
		return "Windows Server 2008 R2"
	case 5:
		return "Windows Server 2012"
	case 6:
		return "Windows Server 2012 R2"
	case 7:
		return "Windows Server 2016"
	case 10:
		return "Windows Server 2025"
	default:
		return fmt.Sprintf("Unknown (%d)", mode)
	}
}

func convertGUID(raw string) string {
	if raw == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) != 16 {
		return raw
	}
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16],
	)
}

// fileTimeToUnix converts a Windows FILETIME (100-ns ticks since 1601-01-01)
// to a Unix timestamp. Returns -1 for zero/unset values.
func fileTimeToUnix(s string) int64 {
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ft <= 0 {
		return -1
	}
	// Offset between Windows epoch (1601) and Unix epoch (1970) in 100-ns units.
	const epochDiff = 116444736000000000
	return (ft - epochDiff) / 10000000
}

// parseWhenCreated converts a generalized time string (20060102150405.0Z)
// to a Unix timestamp.
func parseWhenCreated(s string) int64 {
	if s == "" {
		return 0
	}
	s = strings.TrimSuffix(s, ".0Z")
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func trustDirectionStr(d int64) string {
	switch d {
	case 1:
		return "Inbound"
	case 2:
		return "Outbound"
	case 3:
		return "Bidirectional"
	default:
		return "Disabled"
	}
}

func trustTypeStr(t int64) string {
	switch t {
	case 1:
		return "WINDOWS_NON_ACTIVE_DIRECTORY"
	case 2:
		return "WINDOWS_ACTIVE_DIRECTORY"
	case 3:
		return "MIT"
	default:
		return "UNKNOWN"
	}
}

// extractFSPSID extracts the SID from a ForeignSecurityPrincipal DN.
// e.g. "CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=ludus,DC=domain" → "S-1-5-11"
func extractFSPSID(dn string) string {
	upper := strings.ToUpper(dn)
	if !strings.Contains(upper, "FOREIGNSECURITYPRINCIPALS") {
		return ""
	}
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return ""
	}
	cn := strings.TrimPrefix(parts[0], "CN=")
	cn = strings.TrimPrefix(cn, "cn=")
	if strings.HasPrefix(cn, "S-1-") {
		return cn
	}
	return ""
}
