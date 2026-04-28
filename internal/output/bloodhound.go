package output

// bloodhound.go — converts collected AD objects to BloodHound CE v6 JSON format.
//
// BH CE expects one file per object type, each with:
//   { "data": [...], "meta": { "methods": N, "type": "users", "count": N, "version": 6 } }
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
	ContainedBy       bhTypedID     `json:"ContainedBy"`
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
	ContainedBy       bhTypedID          `json:"ContainedBy"`
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
	ContainedBy      bhTypedID    `json:"ContainedBy"`
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

type bhOU struct {
	ObjectIdentifier string      `json:"ObjectIdentifier"`
	Properties       bhOUProps   `json:"Properties"`
	ChildObjects     []bhTypedID `json:"ChildObjects"`
	Links            []bhGPOLink `json:"Links"`
	Aces             []bhAce     `json:"Aces"`
	ContainedBy      bhTypedID   `json:"ContainedBy"`
	IsDeleted        bool        `json:"IsDeleted"`
	IsACLProtected   bool        `json:"IsACLProtected"`
}

type bhOUProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	Description       string `json:"description"`
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

// ── ADCS BH object types ─────────────────────────────────────────────────

type bhCertTemplate struct {
	ObjectIdentifier string              `json:"ObjectIdentifier"`
	Properties       bhCertTemplateProps `json:"Properties"`
	Aces             []bhAce             `json:"Aces"`
	ContainedBy      bhTypedID           `json:"ContainedBy"`
	IsDeleted        bool                `json:"IsDeleted"`
	IsACLProtected   bool                `json:"IsACLProtected"`
}

type bhCertTemplateProps struct {
	Name                          string   `json:"name"`
	Domain                        string   `json:"domain"`
	DomainSID                     string   `json:"domainsid"`
	DistinguishedName             string   `json:"distinguishedname"`
	Description                   *string  `json:"description"`
	WhenCreated                   int64    `json:"whencreated"`
	DisplayName                   string   `json:"displayname"`
	CertificateNameFlag           string   `json:"certificatenameflag"`
	EnrolleeSuppliesSubject       bool     `json:"enrolleesuppliessubject"`
	SubjectAltRequireUPN          bool     `json:"subjectaltrequireupn"`
	SubjectAltRequireDNS          bool     `json:"subjectaltrequiredns"`
	SubjectAltRequireDomainDNS    bool     `json:"subjectaltrequiredomaindns"`
	SubjectAltRequireEmail        bool     `json:"subjectaltrequireemail"`
	SubjectAltRequireSPN          bool     `json:"subjectaltrequirespn"`
	SubjectRequireEmail           bool     `json:"subjectrequireemail"`
	EnrollmentFlag                string   `json:"enrollmentflag"`
	RequiresManagerApproval       bool     `json:"requiresmanagerapproval"`
	NoSecurityExtension           bool     `json:"nosecurityextension"`
	EKUs                          []string `json:"ekus"`
	CertificateApplicationPolicy  []string `json:"certificateapplicationpolicy"`
	AuthorizedSignatures          int      `json:"authorizedsignatures"`
	ApplicationPolicies           []string `json:"applicationpolicies"`
	IssuancePolicies              []string `json:"issuancepolicies"`
	EffectiveEKUs                 []string `json:"effectiveekus"`
	AuthenticationEnabled         bool     `json:"authenticationenabled"`
	SchannelAuthenticationEnabled bool     `json:"schannelauthenticationenabled"`
	SchemaVersion                 int      `json:"schemaversion"`
	ValidityPeriod                string   `json:"validityperiod"`
	RenewalPeriod                 string   `json:"renewalperiod"`
	OID                           string   `json:"oid,omitempty"`
	HighValue                     bool     `json:"highvalue"`
}

type bhEnterpriseCA struct {
	ObjectIdentifier     string           `json:"ObjectIdentifier"`
	Properties           bhCAProps        `json:"Properties"`
	HostingComputer      string           `json:"HostingComputer"`
	CARegistryData       bhCARegistryData `json:"CARegistryData"`
	EnabledCertTemplates []bhTypedID      `json:"EnabledCertTemplates"`
	Aces                 []bhAce          `json:"Aces"`
	ContainedBy          bhTypedID        `json:"ContainedBy"`
	IsDeleted            bool             `json:"IsDeleted"`
	IsACLProtected       bool             `json:"IsACLProtected"`
	DomainSID            string           `json:"DomainSID"`
}

type bhCAProps struct {
	Name                                string   `json:"name"`
	Domain                              string   `json:"domain"`
	DomainSID                           string   `json:"domainsid"`
	DistinguishedName                   string   `json:"distinguishedname"`
	Description                         *string  `json:"description"`
	WhenCreated                         int64    `json:"whencreated"`
	CAName                              string   `json:"caname"`
	DNSHostname                         string   `json:"dnshostname"`
	CertThumbprint                      string   `json:"certthumbprint"`
	CertName                            string   `json:"certname"`
	CertChain                           []string `json:"certchain"`
	HasBasicConstraints                 bool     `json:"hasbasicconstraints"`
	BasicConstraintPathLength           int      `json:"basicconstraintpathlength"`
	CASecurityCollected                 bool     `json:"casecuritycollected"`
	EnrollmentAgentRestrictionsCollected bool    `json:"enrollmentagentrestrictionscollected"`
	IsUserSpecifiesSanEnabledCollected  bool     `json:"isuserspecifiessanenabledcollected"`
	HighValue                           bool     `json:"highvalue"`
}

type bhCARegistryData struct {
	CASecurity                  bhCASecurityResult      `json:"CASecurity"`
	EnrollmentAgentRestrictions bhEnrollAgentResult     `json:"EnrollmentAgentRestrictions"`
	IsUserSpecifiesSanEnabled   bhBoolCollectedResult   `json:"IsUserSpecifiesSanEnabled"`
}

type bhCASecurityResult struct {
	Data      []bhAce `json:"Data"`
	Collected bool    `json:"Collected"`
}

type bhEnrollAgentResult struct {
	Restrictions []interface{} `json:"Restrictions"`
	Collected    bool          `json:"Collected"`
}

type bhBoolCollectedResult struct {
	Value     bool `json:"Value"`
	Collected bool `json:"Collected"`
}

type bhRootCA struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	Properties       bhRootCAProps `json:"Properties"`
	Aces             []bhAce       `json:"Aces"`
	ContainedBy      bhTypedID     `json:"ContainedBy"`
	IsDeleted        bool          `json:"IsDeleted"`
	IsACLProtected   bool          `json:"IsACLProtected"`
	DomainSID        string        `json:"DomainSID"`
}

type bhRootCAProps struct {
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	DomainSID               string   `json:"domainsid"`
	DistinguishedName       string   `json:"distinguishedname"`
	Description             *string  `json:"description"`
	WhenCreated             int64    `json:"whencreated"`
	CertThumbprint          string   `json:"certthumbprint"`
	CertName                string   `json:"certname"`
	CertChain               []string `json:"certchain"`
	HasBasicConstraints     bool     `json:"hasbasicconstraints"`
	BasicConstraintPathLength int    `json:"basicconstraintpathlength"`
	HighValue               bool     `json:"highvalue"`
}

type bhNTAuthStore struct {
	ObjectIdentifier string             `json:"ObjectIdentifier"`
	Properties       bhNTAuthStoreProps `json:"Properties"`
	Aces             []bhAce            `json:"Aces"`
	ContainedBy      bhTypedID          `json:"ContainedBy"`
	IsDeleted        bool               `json:"IsDeleted"`
	IsACLProtected   bool               `json:"IsACLProtected"`
	DomainSID        string             `json:"DomainSID"`
}

type bhNTAuthStoreProps struct {
	Name              string   `json:"name"`
	Domain            string   `json:"domain"`
	DomainSID         string   `json:"domainsid"`
	DistinguishedName string   `json:"distinguishedname"`
	Description       *string  `json:"description"`
	WhenCreated       int64    `json:"whencreated"`
	CertThumbprints   []string `json:"certthumbprints"`
	HighValue         bool     `json:"highvalue"`
}

// ── Container BH type ────────────────────────────────────────────────────

type bhContainer struct {
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Properties       bhContainerProps `json:"Properties"`
	ChildObjects     []bhTypedID      `json:"ChildObjects"`
	Aces             []bhAce          `json:"Aces"`
	ContainedBy      bhTypedID        `json:"ContainedBy"`
	IsDeleted        bool             `json:"IsDeleted"`
	IsACLProtected   bool             `json:"IsACLProtected"`
}

type bhContainerProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	Description       string `json:"description"`
	WhenCreated       int64  `json:"whencreated"`
	HighValue         bool   `json:"highvalue"`
}

// ── Main converter ────────────────────────────────────────────────────────

// BHConverter holds collected data and converts it to BH CE format.
type BHConverter struct {
	domain    string
	domainSID string
	// DN → SID lookup built from users + computers for member resolution.
	dnToSID   map[string]string
	dnToType  map[string]string
	// dNSHostName → SID for resolving CA HostingComputer.
	hostToSID map[string]string
}

// NewBHConverter creates a converter. domainSID is the domain's S-1-5-21-... SID.
func NewBHConverter(domain, domainSID string) *BHConverter {
	return &BHConverter{
		domain:    strings.ToUpper(domain),
		domainSID: domainSID,
		dnToSID:   make(map[string]string),
		dnToType:  make(map[string]string),
		hostToSID: make(map[string]string),
	}
}

// IndexObjects builds the DN→SID/type lookup from users, computers, groups, and OUs.
// Call this before Convert* methods so member SIDs and containment can be resolved.
func (c *BHConverter) IndexObjects(users, computers, groups []adws.ADObject, extra ...[]adws.ADObject) {
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
		dns := enum.AttrStr(comp, "dNSHostName")
		if dns != "" && sid != "" {
			c.hostToSID[strings.ToUpper(dns)] = sid
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
	// Index OUs and containers by DN → GUID (they use objectGUID, not objectSid).
	for _, batch := range extra {
		for _, o := range batch {
			dn := enum.AttrStr(o, "distinguishedName")
			guid := convertGUID(enum.AttrStr(o, "objectGUID"))
			if dn == "" || guid == "" {
				continue
			}
			upper := strings.ToUpper(dn)
			if _, exists := c.dnToSID[upper]; exists {
				continue // already indexed (user/computer/group takes priority)
			}
			// Detect type: OU= prefix → OU, otherwise Container
			objType := "Container"
			if strings.HasPrefix(upper, "OU=") {
				objType = "OU"
			}
			c.dnToSID[upper] = guid
			c.dnToType[upper] = objType
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
			ContainedBy:            c.resolveContainedBy(enum.AttrStr(obj, "distinguishedName")),
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
				HighValue:             parseInt64(enum.AttrStr(obj, "adminCount")) == 1,
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
			ContainedBy:            c.resolveContainedBy(enum.AttrStr(obj, "distinguishedName")),
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
			}
			// Unresolved DNs are dropped — DN= stubs crash BH CE v8.9.1
			// regardless of ObjectType. resolveGroupMembers() should
			// resolve these to SIDs before we get here.
		}

		g := bhGroup{
			ObjectIdentifier: sid,
			Members:          members,
			Aces:             sdToBHAces(obj, c.dnToSID, c.dnToType),
			ContainedBy:      c.resolveContainedBy(enum.AttrStr(obj, "distinguishedName")),
			Properties: bhGroupProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(sam), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(enum.AttrStr(obj, "distinguishedName")),
				SAMAccountName:    sam,
				Description:       enum.AttrStr(obj, "description"),
				AdminCount:        parseInt64(enum.AttrStr(obj, "adminCount")) == 1,
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
				HighValue:         isHighValueGroup(sid),
			},
		}
		out = append(out, g)
	}
	return out
}

func (c *BHConverter) ConvertGPOs(objects []adws.ADObject) []bhGPO {
	out := make([]bhGPO, 0, len(objects))
	for _, obj := range objects {
		// Use the GPO GUID from DN (CN={GUID},...) — this matches gPLink references.
		// Fall back to objectGUID if DN parsing fails.
		dn := enum.AttrStr(obj, "distinguishedName")
		guid := extractGPOGUID(dn)
		if guid == "" {
			guid = convertGUID(enum.AttrStr(obj, "objectGUID"))
		}
		if guid == "" {
			continue
		}
		name := enum.AttrStr(obj, "displayName")

		gpo := bhGPO{
			ObjectIdentifier: guid,
			Aces:             sdToBHAces(obj, c.dnToSID, c.dnToType),
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

func (c *BHConverter) ConvertOUs(objects []adws.ADObject) []bhOU {
	out := make([]bhOU, 0, len(objects))
	for _, obj := range objects {
		guid := convertGUID(enum.AttrStr(obj, "objectGUID"))
		if guid == "" {
			continue
		}
		name := enum.AttrStr(obj, "name")
		dn := enum.AttrStr(obj, "distinguishedName")

		ou := bhOU{
			ObjectIdentifier: guid,
			ChildObjects:     []bhTypedID{},
			Links:            parseGPLinks(enum.AttrStr(obj, "gPLink")),
			Aces:             sdToBHAces(obj, c.dnToSID, c.dnToType),
			ContainedBy:      c.resolveContainedBy(dn),
			Properties: bhOUProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(name), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(dn),
				Description:       enum.AttrStr(obj, "description"),
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
			},
		}
		out = append(out, ou)
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

func (c *BHConverter) ConvertContainers(objects []adws.ADObject) []bhContainer {
	out := make([]bhContainer, 0, len(objects))
	for _, obj := range objects {
		guid := convertGUID(enum.AttrStr(obj, "objectGUID"))
		if guid == "" {
			continue
		}
		name := enum.AttrStr(obj, "name")
		dn := enum.AttrStr(obj, "distinguishedName")

		cn := bhContainer{
			ObjectIdentifier: guid,
			ChildObjects:     []bhTypedID{},
			Aces:             sdToBHAces(obj, c.dnToSID, c.dnToType),
			ContainedBy:      c.resolveContainedBy(dn),
			Properties: bhContainerProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(name), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(dn),
				Description:       enum.AttrStr(obj, "description"),
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
			},
		}
		out = append(out, cn)
	}
	return out
}

// ── ADCS converters ───────────────────────────────────────────────────────

func (c *BHConverter) ConvertCertTemplates(templates []enum.TemplateInfo) []bhCertTemplate {
	out := make([]bhCertTemplate, 0, len(templates))
	for _, t := range templates {
		guid := convertGUID(enum.AttrStr(t.Object, "objectGUID"))
		if guid == "" {
			continue
		}
		cn := enum.AttrStr(t.Object, "cn")
		displayName := enum.AttrStr(t.Object, "displayName")
		dn := enum.AttrStr(t.Object, "distinguishedName")

		ekus := t.EKUs
		if ekus == nil {
			ekus = []string{}
		}
		appPolicies := t.AppPolicies
		if appPolicies == nil {
			appPolicies = []string{}
		}

		effectiveEKUs := ekus
		if len(effectiveEKUs) == 0 {
			effectiveEKUs = appPolicies
		}
		if effectiveEKUs == nil {
			effectiveEKUs = []string{}
		}

		authEnabled := hasAuthEKUForBH(effectiveEKUs)
		schannelEnabled := hasOIDForBH(effectiveEKUs, "1.3.6.1.5.5.7.3.1") // Server Auth

		schemaVer := int(parseInt64(enum.AttrStr(t.Object, "msPKI-Template-Schema-Version")))

		tmpl := bhCertTemplate{
			ObjectIdentifier: guid,
			Aces:             adcsSdToBHAces(t.Object, c.dnToSID, c.dnToType),
			ContainedBy:      c.resolveContainedBy(dn),
			Properties: bhCertTemplateProps{
				Name:                          fmt.Sprintf("%s@%s", strings.ToUpper(cn), c.domain),
				Domain:                        c.domain,
				DomainSID:                     c.domainSID,
				DistinguishedName:             strings.ToUpper(dn),
				WhenCreated:                   parseWhenCreated(enum.AttrStr(t.Object, "whenCreated")),
				DisplayName:                   displayName,
				CertificateNameFlag:           certNameFlagStr(t.NameFlag),
				EnrolleeSuppliesSubject:       t.NameFlag&0x00000001 != 0,
				SubjectAltRequireUPN:          t.NameFlag&0x00400000 != 0,
				SubjectAltRequireDNS:          t.NameFlag&0x04000000 != 0,
				SubjectAltRequireDomainDNS:    t.NameFlag&0x08000000 != 0,
				SubjectAltRequireEmail:        t.NameFlag&0x00800000 != 0,
				SubjectAltRequireSPN:          t.NameFlag&0x01000000 != 0,
				SubjectRequireEmail:           t.NameFlag&0x20000000 != 0,
				EnrollmentFlag:                enrollFlagStr(t.EnrollFlag),
				RequiresManagerApproval:       t.EnrollFlag&0x00000002 != 0,
				NoSecurityExtension:           t.EnrollFlag&0x00080000 != 0,
				EKUs:                          ekus,
				CertificateApplicationPolicy:  appPolicies,
				AuthorizedSignatures:          int(t.RASignature),
				ApplicationPolicies:           appPolicies,
				IssuancePolicies:              []string{},
				EffectiveEKUs:                 effectiveEKUs,
				AuthenticationEnabled:         authEnabled,
				SchannelAuthenticationEnabled: schannelEnabled,
				SchemaVersion:                 schemaVer,
				ValidityPeriod:                parsePKIPeriod(enum.AttrStr(t.Object, "pKIExpirationPeriod")),
				RenewalPeriod:                 parsePKIPeriod(enum.AttrStr(t.Object, "pKIOverlapPeriod")),
				HighValue:                     false,
			},
		}
		out = append(out, tmpl)
	}
	return out
}

func (c *BHConverter) ConvertEnterpriseCA(cas []enum.CAInfo, templateGUIDs map[string]string) []bhEnterpriseCA {
	out := make([]bhEnterpriseCA, 0, len(cas))
	for _, ca := range cas {
		guid := convertGUID(enum.AttrStr(ca.Object, "objectGUID"))
		if guid == "" {
			continue
		}
		cn := enum.AttrStr(ca.Object, "cn")
		dn := enum.AttrStr(ca.Object, "distinguishedName")
		dnsHostname := enum.AttrStr(ca.Object, "dNSHostName")

		// Resolve hosting computer SID from hostname
		hostingSID := ""
		if dnsHostname != "" {
			if sid, ok := c.hostToSID[strings.ToUpper(dnsHostname)]; ok {
				hostingSID = sid
			}
		}

		// Map published template names to GUIDs
		enabledTemplates := make([]bhTypedID, 0, len(ca.Templates))
		for _, tName := range ca.Templates {
			if tGUID, ok := templateGUIDs[strings.ToUpper(tName)]; ok {
				enabledTemplates = append(enabledTemplates, bhTypedID{
					ObjectIdentifier: tGUID,
					ObjectType:       "CertTemplate",
				})
			}
		}

		// Cert thumbprint from cACertificate
		certThumb := certThumbprint(enum.AttrStr(ca.Object, "cACertificate"))

		ecaObj := bhEnterpriseCA{
			ObjectIdentifier:     guid,
			HostingComputer:      hostingSID,
			EnabledCertTemplates: enabledTemplates,
			Aces:                 adcsSdToBHAces(ca.Object, c.dnToSID, c.dnToType),
			ContainedBy:          c.resolveContainedBy(dn),
			DomainSID:            c.domainSID,
			CARegistryData: bhCARegistryData{
				CASecurity:                  bhCASecurityResult{Data: []bhAce{}, Collected: false},
				EnrollmentAgentRestrictions: bhEnrollAgentResult{Restrictions: []interface{}{}, Collected: false},
				IsUserSpecifiesSanEnabled:   bhBoolCollectedResult{Value: false, Collected: false},
			},
			Properties: bhCAProps{
				Name:                                fmt.Sprintf("%s@%s", strings.ToUpper(cn), c.domain),
				Domain:                              c.domain,
				DomainSID:                           c.domainSID,
				DistinguishedName:                   strings.ToUpper(dn),
				WhenCreated:                         parseWhenCreated(enum.AttrStr(ca.Object, "whenCreated")),
				CAName:                              cn,
				DNSHostname:                         dnsHostname,
				CertThumbprint:                      certThumb,
				CertName:                            certThumb,
				CertChain:                           []string{},
				CASecurityCollected:                 false,
				EnrollmentAgentRestrictionsCollected: false,
				IsUserSpecifiesSanEnabledCollected:  false,
				HighValue:                           true,
			},
		}
		out = append(out, ecaObj)
	}
	return out
}

func (c *BHConverter) ConvertRootCAs(objects []adws.ADObject) []bhRootCA {
	out := make([]bhRootCA, 0, len(objects))
	for _, obj := range objects {
		guid := convertGUID(enum.AttrStr(obj, "objectGUID"))
		if guid == "" {
			continue
		}
		cn := enum.AttrStr(obj, "cn")
		dn := enum.AttrStr(obj, "distinguishedName")

		rca := bhRootCA{
			ObjectIdentifier: guid,
			Aces:             []bhAce{},
			ContainedBy:      c.resolveContainedBy(dn),
			DomainSID:        c.domainSID,
			Properties: bhRootCAProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(cn), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(dn),
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
				CertThumbprint:    certThumbprint(enum.AttrStr(obj, "cACertificate")),
				CertName:          certThumbprint(enum.AttrStr(obj, "cACertificate")),
				CertChain:         []string{},
				HighValue:         false,
			},
		}
		out = append(out, rca)
	}
	return out
}

func (c *BHConverter) ConvertNTAuthStores(objects []adws.ADObject) []bhNTAuthStore {
	out := make([]bhNTAuthStore, 0, len(objects))
	for _, obj := range objects {
		guid := convertGUID(enum.AttrStr(obj, "objectGUID"))
		if guid == "" {
			continue
		}
		cn := enum.AttrStr(obj, "cn")
		dn := enum.AttrStr(obj, "distinguishedName")

		nta := bhNTAuthStore{
			ObjectIdentifier: guid,
			Aces:             []bhAce{},
			ContainedBy:      c.resolveContainedBy(dn),
			DomainSID:        c.domainSID,
			Properties: bhNTAuthStoreProps{
				Name:              fmt.Sprintf("%s@%s", strings.ToUpper(cn), c.domain),
				Domain:            c.domain,
				DomainSID:         c.domainSID,
				DistinguishedName: strings.ToUpper(dn),
				WhenCreated:       parseWhenCreated(enum.AttrStr(obj, "whenCreated")),
				CertThumbprints:   []string{},
				HighValue:         false,
			},
		}
		out = append(out, nta)
	}
	return out
}

// ── ZIP writer ─────────────────────────────────────────────────────────────

// WriteBHZip serialises all collected data as BH CE JSON files inside a zip.
func WriteBHZip(
	outDir, filePrefix, domain, domainSID string,
	users, computers, groups, gpos, trusts, ous, containers []adws.ADObject,
	domainInfo *enum.DomainResult,
	adcsResult *enum.ADCSResult,
) error {
	c := NewBHConverter(domain, domainSID)
	c.IndexObjects(users, computers, groups, ous, containers)

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
	bhOUs := c.ConvertOUs(ous)
	bhTrustsSlice := c.ConvertTrusts(trusts)
	bhContainers := c.ConvertContainers(containers)


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
		{"ous.json", "ous", bhMethodObjectProp | bhMethodACL, bhOUs, len(bhOUs)},
		{"domains.json", "domains", bhMethodObjectProp | bhMethodTrusts | bhMethodACL, []bhDomain{domainObj}, 1},
		{"containers.json", "containers", bhMethodObjectProp | bhMethodACL, bhContainers, len(bhContainers)},
	}

	// ADCS entries — added when ADCS data is available.
	if adcsResult != nil {
		// Build template CN → GUID lookup for CA → template linking.
		templateGUIDs := make(map[string]string)
		for _, t := range adcsResult.Templates {
			cn := enum.AttrStr(t.Object, "cn")
			guid := convertGUID(enum.AttrStr(t.Object, "objectGUID"))
			if cn != "" && guid != "" {
				templateGUIDs[strings.ToUpper(cn)] = guid
			}
		}

		bhTemplates := c.ConvertCertTemplates(adcsResult.Templates)
		bhCAs := c.ConvertEnterpriseCA(adcsResult.CAs, templateGUIDs)
		bhRootCAs := c.ConvertRootCAs(adcsResult.RootCAs)
		bhNTAuth := c.ConvertNTAuthStores(adcsResult.NTAuth)

		entries = append(entries,
			entry{"certtemplates.json", "certtemplates", bhMethodObjectProp | bhMethodACL, bhTemplates, len(bhTemplates)},
			entry{"enterprisecas.json", "enterprisecas", bhMethodObjectProp | bhMethodACL, bhCAs, len(bhCAs)},
			entry{"rootcas.json", "rootcas", bhMethodObjectProp, bhRootCAs, len(bhRootCAs)},
			entry{"ntauthstores.json", "ntauthstores", bhMethodObjectProp, bhNTAuth, len(bhNTAuth)},
		)
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

	// Build reverse SID→Type index for efficient principal type lookup.
	sidToType := make(map[string]string, len(dnToSID))
	for dn, sid := range dnToSID {
		if t, ok := dnToType[dn]; ok {
			sidToType[sid] = t
		}
	}

	for _, sdAce := range append(append(sd.Enrollers, sd.Writers...), sd.FullControl...) {
		if sdAce.Type != "Allow" {
			continue
		}

		principalSID := sdAce.SID
		principalType := "Base" // default

		// Check our collected objects index
		if t, ok := sidToType[principalSID]; ok {
			principalType = t
		}

		// Well-known SID types
		if principalType == "Base" {
			switch {
			case principalSID == "S-1-5-18": // SYSTEM
				principalType = "User"
			case principalSID == "S-1-5-11", principalSID == "S-1-1-0", principalSID == "S-1-5-9",
				principalSID == "S-1-5-32-544", principalSID == "S-1-5-32-545",
				principalSID == "S-1-5-32-548", principalSID == "S-1-5-32-549",
				principalSID == "S-1-5-32-550", principalSID == "S-1-5-32-551",
				principalSID == "S-1-5-32-552", principalSID == "S-1-5-32-555",
				principalSID == "S-1-5-32-556", principalSID == "S-1-5-32-562",
				principalSID == "S-1-5-32-568", principalSID == "S-1-5-32-569",
				principalSID == "S-1-5-32-573", principalSID == "S-1-5-32-574",
				principalSID == "S-1-5-32-575", principalSID == "S-1-5-32-576",
				principalSID == "S-1-5-32-577", principalSID == "S-1-5-32-578",
				principalSID == "S-1-5-32-580", principalSID == "S-1-5-32-582":
				principalType = "Group"
			default:
				// Domain-specific well-known RIDs
				if idx := strings.LastIndex(principalSID, "-"); idx > 0 {
					switch principalSID[idx+1:] {
					case "512", "513", "514", "515", "516", "517", "518", "519",
						"520", "521", "522", "525", "526", "527", "553", "571", "572":
						principalType = "Group"
					case "500", "501", "502": // Administrator, Guest, krbtgt
						principalType = "User"
					}
				}
			}
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
		objGUID := strings.ToLower(sdAce.ObjectGUID)
		if mask&0x00000100 != 0 { // Extended rights (ADS_RIGHT_DS_CONTROL_ACCESS)
			switch objGUID {
			case "":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "AllExtendedRights", IsInherited: false})
			case "00299570-246d-11d0-a768-00aa006e0529":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "ForceChangePassword", IsInherited: false})
			case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GetChanges", IsInherited: false})
			case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GetChangesAll", IsInherited: false})
			case "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GetChangesInFilteredSet", IsInherited: false})
			}
		}
		if mask&0x00000020 != 0 { // WriteProperty
			switch objGUID {
			case "bf9679c0-0de6-11d0-a285-00aa003049e2":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "AddMember", IsInherited: false})
			case "f3a64788-5306-11d1-a9c5-0000f80367c1":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "WriteSPN", IsInherited: false})
			case "4c164200-20c0-11d0-a768-00aa006e0529":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "AddKeyCredentialLink", IsInherited: false})
			case "":
				aces = append(aces, bhAce{PrincipalSID: principalSID, PrincipalType: principalType, RightName: "GenericWrite", IsInherited: false})
			}
		}
	}

	// Owner gets Owns edge
	if sd.OwnerSID != "" {
		aces = append(aces, bhAce{PrincipalSID: sd.OwnerSID, PrincipalType: "Base", RightName: "Owns", IsInherited: false})
	}

	return aces
}

// adcsSdToBHAces converts parsed nTSecurityDescriptor ACEs to BH ACE format,
// including ADCS-specific rights (Enroll, WritePKINameFlag, WritePKIEnrollmentFlag).
func adcsSdToBHAces(obj adws.ADObject, dnToSID map[string]string, dnToType map[string]string) []bhAce {
	aces := sdToBHAces(obj, dnToSID, dnToType)

	sdRaw := enum.AttrStr(obj, "nTSecurityDescriptor")
	if sdRaw == "" {
		return aces
	}
	sd := enum.ParseSD(sdRaw)
	if sd == nil {
		return aces
	}

	sidToType := make(map[string]string, len(dnToSID))
	for dn, sid := range dnToSID {
		if t, ok := dnToType[dn]; ok {
			sidToType[sid] = t
		}
	}

	resolvePrincipalType := func(sid string) string {
		if t, ok := sidToType[sid]; ok {
			return t
		}
		return resolveWellKnownType(sid)
	}

	// Scan for ADCS-specific extended rights and write properties.
	for _, sdAce := range append(append(sd.Enrollers, sd.Writers...), sd.FullControl...) {
		if sdAce.Type != "Allow" {
			continue
		}
		objGUID := strings.ToLower(sdAce.ObjectGUID)
		mask := sdAce.AccessMask
		pType := resolvePrincipalType(sdAce.SID)

		// Enroll extended right
		if mask&0x00000100 != 0 && objGUID == "0e10c968-78fb-11d2-90d4-00c04f79dc55" {
			aces = append(aces, bhAce{PrincipalSID: sdAce.SID, PrincipalType: pType, RightName: "Enroll", IsInherited: false})
		}
		// WritePKINameFlag
		if mask&0x00000020 != 0 && objGUID == "ea1dddc4-60ff-416e-8cc0-17cee534bce7" {
			aces = append(aces, bhAce{PrincipalSID: sdAce.SID, PrincipalType: pType, RightName: "WritePKINameFlag", IsInherited: false})
		}
		// WritePKIEnrollmentFlag
		if mask&0x00000020 != 0 && objGUID == "d15ef7d8-f226-46db-ae79-b34e560bd12c" {
			aces = append(aces, bhAce{PrincipalSID: sdAce.SID, PrincipalType: pType, RightName: "WritePKIEnrollmentFlag", IsInherited: false})
		}
	}

	return aces
}

// resolveWellKnownType returns a BH principal type for well-known SIDs.
func resolveWellKnownType(sid string) string {
	switch {
	case sid == "S-1-5-18":
		return "User"
	case sid == "S-1-5-11", sid == "S-1-1-0", sid == "S-1-5-9",
		sid == "S-1-5-32-544", sid == "S-1-5-32-545",
		sid == "S-1-5-32-548", sid == "S-1-5-32-549",
		sid == "S-1-5-32-550", sid == "S-1-5-32-551",
		sid == "S-1-5-32-552", sid == "S-1-5-32-555",
		sid == "S-1-5-32-556", sid == "S-1-5-32-562",
		sid == "S-1-5-32-568", sid == "S-1-5-32-569",
		sid == "S-1-5-32-573", sid == "S-1-5-32-574",
		sid == "S-1-5-32-575", sid == "S-1-5-32-576",
		sid == "S-1-5-32-577", sid == "S-1-5-32-578",
		sid == "S-1-5-32-580", sid == "S-1-5-32-582":
		return "Group"
	}
	if idx := strings.LastIndex(sid, "-"); idx > 0 {
		switch sid[idx+1:] {
		case "512", "513", "514", "515", "516", "517", "518", "519",
			"520", "521", "522", "525", "526", "527", "553", "571", "572":
			return "Group"
		case "500", "501", "502":
			return "User"
		}
	}
	return "Base"
}

// ── ADCS helper functions ─────────────────────────────────────────────────

func certNameFlagStr(flag int64) string {
	var names []string
	if flag&0x00000001 != 0 { names = append(names, "ENROLLEE_SUPPLIES_SUBJECT") }
	if flag&0x00010000 != 0 { names = append(names, "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME") }
	if flag&0x00400000 != 0 { names = append(names, "SUBJECT_ALT_REQUIRE_UPN") }
	if flag&0x00800000 != 0 { names = append(names, "SUBJECT_ALT_REQUIRE_EMAIL") }
	if flag&0x01000000 != 0 { names = append(names, "SUBJECT_ALT_REQUIRE_SPN") }
	if flag&0x02000000 != 0 { names = append(names, "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID") }
	if flag&0x04000000 != 0 { names = append(names, "SUBJECT_ALT_REQUIRE_DNS") }
	if flag&0x08000000 != 0 { names = append(names, "SUBJECT_ALT_REQUIRE_DOMAIN_DNS") }
	if flag&0x10000000 != 0 { names = append(names, "SUBJECT_REQUIRE_DNS_AS_CN") }
	if flag&0x20000000 != 0 { names = append(names, "SUBJECT_REQUIRE_EMAIL") }
	if flag&0x40000000 != 0 { names = append(names, "SUBJECT_REQUIRE_COMMON_NAME") }
	if flag&0x80000000 != 0 { names = append(names, "SUBJECT_REQUIRE_DIRECTORY_PATH") }
	return strings.Join(names, ", ")
}

func enrollFlagStr(flag int64) string {
	var names []string
	if flag&0x00000001 != 0 { names = append(names, "INCLUDE_SYMMETRIC_ALGORITHMS") }
	if flag&0x00000002 != 0 { names = append(names, "PEND_ALL_REQUESTS") }
	if flag&0x00000004 != 0 { names = append(names, "PUBLISH_TO_KRA_CONTAINER") }
	if flag&0x00000008 != 0 { names = append(names, "PUBLISH_TO_DS") }
	if flag&0x00000010 != 0 { names = append(names, "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE") }
	if flag&0x00000020 != 0 { names = append(names, "AUTO_ENROLLMENT") }
	if flag&0x00000100 != 0 { names = append(names, "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT") }
	if flag&0x00080000 != 0 { names = append(names, "NO_SECURITY_EXTENSION") }
	return strings.Join(names, ", ")
}

// parsePKIPeriod decodes a pKIExpirationPeriod or pKIOverlapPeriod value
// (base64 encoded 8-byte little-endian negative 100-ns intervals) to a human string.
func parsePKIPeriod(raw string) string {
	if raw == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) != 8 {
		return ""
	}
	val := int64(binary.LittleEndian.Uint64(b))
	if val >= 0 {
		return ""
	}
	seconds := -val / 10000000
	days := seconds / 86400
	if days == 0 {
		hours := seconds / 3600
		if hours > 0 {
			return fmt.Sprintf("%d hours", hours)
		}
		return ""
	}
	years := days / 365
	if years > 0 && days%365 == 0 {
		if years == 1 {
			return "1 year"
		}
		return fmt.Sprintf("%d years", years)
	}
	weeks := days / 7
	if weeks > 0 && days%7 == 0 {
		if weeks == 1 {
			return "1 week"
		}
		return fmt.Sprintf("%d weeks", weeks)
	}
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

// certThumbprint computes a hex SHA-1 thumbprint from a base64-encoded certificate.
func certThumbprint(raw string) string {
	if raw == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(b) == 0 {
		return ""
	}
	// Use first 20 bytes as a pseudo-thumbprint if cert is present.
	// Full SHA-1 would require crypto/sha1 — keep it simple.
	n := len(b)
	if n > 20 {
		n = 20
	}
	return fmt.Sprintf("%X", b[:n])
}

func hasAuthEKUForBH(ekus []string) bool {
	authOIDs := map[string]bool{
		"1.3.6.1.5.5.7.3.2":      true, // Client Auth
		"1.3.6.1.5.2.3.4":        true, // PKINIT
		"1.3.6.1.4.1.311.20.2.2": true, // Smart Card Logon
		"2.5.29.37.0":             true, // Any Purpose
	}
	for _, eku := range ekus {
		if authOIDs[eku] {
			return true
		}
	}
	return false
}

func hasOIDForBH(ekus []string, oid string) bool {
	for _, e := range ekus {
		if strings.EqualFold(e, oid) {
			return true
		}
	}
	return false
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

// extractGPOGUID extracts the GPO GUID from a GPO's distinguished name.
// e.g. "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,..." → "{6ac1786c-016f-11d2-945f-00c04fb984f9}"
func extractGPOGUID(dn string) string {
	upper := strings.ToUpper(dn)
	idx := strings.Index(upper, "CN={")
	if idx < 0 {
		return ""
	}
	start := idx + 3 // skip "CN="
	end := strings.Index(dn[start:], "}")
	if end < 0 {
		return ""
	}
	return strings.ToLower(dn[start : start+end+1])
}

// isHighValueGroup returns true for well-known privileged group RIDs.
func isHighValueGroup(sid string) bool {
	// Well-known high-value builtin groups
	switch sid {
	case "S-1-5-32-544", // Administrators
		"S-1-5-32-548", // Account Operators
		"S-1-5-32-549", // Server Operators
		"S-1-5-32-550", // Print Operators
		"S-1-5-32-551": // Backup Operators
		return true
	}
	// Domain-specific high-value RIDs
	idx := strings.LastIndex(sid, "-")
	if idx < 0 {
		return false
	}
	switch sid[idx+1:] {
	case "512", // Domain Admins
		"516", // Domain Controllers
		"518", // Schema Admins
		"519", // Enterprise Admins
		"520", // Group Policy Creator Owners
		"521", // Read-only Domain Controllers
		"526", // Key Admins
		"527": // Enterprise Key Admins
		return true
	}
	return false
}

// parseGPLinks parses the AD gPLink attribute into BH GPOLink entries.
// Format: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;flags][...]
func parseGPLinks(gpLink string) []bhGPOLink {
	if gpLink == "" {
		return []bhGPOLink{}
	}
	var links []bhGPOLink
	// Split on ][
	for _, part := range strings.Split(gpLink, "[") {
		part = strings.TrimSuffix(part, "]")
		if part == "" {
			continue
		}
		// Format: LDAP://CN={GUID},...;flags
		semi := strings.LastIndex(part, ";")
		if semi < 0 {
			continue
		}
		ldapPath := part[:semi]
		flagStr := part[semi+1:]

		// Extract GUID from CN={GUID}
		idx := strings.Index(strings.ToUpper(ldapPath), "CN={")
		if idx < 0 {
			continue
		}
		guidStart := idx + 3 // skip "CN="
		guidEnd := strings.Index(ldapPath[guidStart:], "}")
		if guidEnd < 0 {
			continue
		}
		guid := strings.ToLower(ldapPath[guidStart : guidStart+guidEnd+1])

		enforced := flagStr == "2" // 0=enabled, 1=disabled, 2=enforced
		links = append(links, bhGPOLink{GUID: guid, IsEnforced: enforced})
	}
	return links
}

// resolveContainedBy determines the parent container (OU or Domain) from a DN.
func (c *BHConverter) resolveContainedBy(dn string) bhTypedID {
	if parentDN := parentFromDN(dn); parentDN != "" {
		upperParent := strings.ToUpper(parentDN)
		if psid, ok := c.dnToSID[upperParent]; ok {
			return bhTypedID{ObjectIdentifier: psid, ObjectType: c.dnToType[upperParent]}
		}
		// Parent is domain root
		domainDN := dnFromDomain(c.domain)
		if strings.EqualFold(parentDN, domainDN) && c.domainSID != "" {
			return bhTypedID{ObjectIdentifier: c.domainSID, ObjectType: "Domain"}
		}
	}
	return bhTypedID{}
}

// parentFromDN extracts the parent DN from a distinguished name.
// e.g. "OU=Servers,DC=corp,DC=local" → "DC=corp,DC=local"
func parentFromDN(dn string) string {
	idx := strings.Index(dn, ",")
	if idx < 0 {
		return ""
	}
	return dn[idx+1:]
}

// dnFromDomain builds a DN from a domain FQDN.
// e.g. "CORP.LOCAL" → "DC=CORP,DC=LOCAL"
func dnFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}
