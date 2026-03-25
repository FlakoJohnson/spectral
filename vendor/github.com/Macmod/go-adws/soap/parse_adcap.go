package soap

import (
	"encoding/xml"
	"fmt"
)

// NameTranslateResult represents the output element for MS-ADCAP TranslateName.
// Result==0 indicates success; non-zero values correspond to DRS name crack results.
type NameTranslateResult struct {
	Name   string
	Result uint32
}

type translateNameEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		TranslateNameResponse *translateNameResponseXML `xml:"TranslateNameResponse,omitempty"`
		Fault                 *Fault                    `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type translateNameResponseXML struct {
	NameTranslateResult *arrayOfActiveDirectoryNameTranslateResultXML `xml:"NameTranslateResult"`
}

type arrayOfActiveDirectoryNameTranslateResultXML struct {
	Results []activeDirectoryNameTranslateResultXML `xml:"ActiveDirectoryNameTranslateResult"`
}

type activeDirectoryNameTranslateResultXML struct {
	Name   string `xml:"Name"`
	Result uint32 `xml:"Result"`
}

// ADCAPActiveDirectoryObject is the decoded subset of MS-ADCAP ActiveDirectoryObject.
// It is used by multiple MS-ADCAP operations that return principals/groups.
type ADCAPActiveDirectoryObject struct {
	DistinguishedName string   `xml:"DistinguishedName"`
	Name              string   `xml:"Name"`
	ObjectClass       string   `xml:"ObjectClass"`
	ObjectGuid        string   `xml:"ObjectGuid"`
	ObjectTypes       []string `xml:"ObjectTypes>string"`
	ReferenceServer   string   `xml:"ReferenceServer"`
}

// ADCAPActiveDirectoryPrincipal is the decoded subset of MS-ADCAP ActiveDirectoryPrincipal.
type ADCAPActiveDirectoryPrincipal struct {
	ADCAPActiveDirectoryObject
	SID            string `xml:"SID"`
	SamAccountName string `xml:"SamAccountName"`
}

// ADCAPActiveDirectoryGroup is the decoded subset of MS-ADCAP ActiveDirectoryGroup.
type ADCAPActiveDirectoryGroup struct {
	ADCAPActiveDirectoryPrincipal
	GroupScope string `xml:"GroupScope"`
	GroupType  string `xml:"GroupType"`
}

type arrayOfActiveDirectoryPrincipalXML struct {
	Items []ADCAPActiveDirectoryPrincipal `xml:"ActiveDirectoryPrincipal"`
}

type arrayOfActiveDirectoryGroupXML struct {
	Items []ADCAPActiveDirectoryGroup `xml:"ActiveDirectoryGroup"`
}

type getADGroupMemberEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetADGroupMemberResponse *getADGroupMemberResponseXML `xml:"GetADGroupMemberResponse"`
		Fault                    *Fault                       `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getADPrincipalAuthorizationGroupEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetADPrincipalAuthorizationGroupResponse *getADPrincipalAuthorizationGroupResponseXML `xml:"GetADPrincipalAuthorizationGroupResponse"`
		Fault                                    *Fault                                       `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getADPrincipalGroupMembershipEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetADPrincipalGroupMembershipResponse *getADPrincipalGroupMembershipResponseXML `xml:"GetADPrincipalGroupMembershipResponse"`
		Fault                                 *Fault                                    `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getADGroupMemberResponseXML struct {
	Members *arrayOfActiveDirectoryPrincipalXML `xml:"Members"`
}

type getADPrincipalAuthorizationGroupResponseXML struct {
	MemberOf *arrayOfActiveDirectoryGroupXML `xml:"MemberOf"`
}

type getADPrincipalGroupMembershipResponseXML struct {
	MemberOf *arrayOfActiveDirectoryGroupXML `xml:"MemberOf"`
}

// ADCAPActiveDirectoryPartition is the decoded subset of MS-ADCAP ActiveDirectoryPartition.
type ADCAPActiveDirectoryPartition struct {
	ADCAPActiveDirectoryObject
	DNSRoot                        string   `xml:"DNSRoot"`
	DeletedObjectsContainer        string   `xml:"DeletedObjectsContainer"`
	LostAndFoundContainer          string   `xml:"LostAndFoundContainer"`
	QuotasContainer                string   `xml:"QuotasContainer"`
	ReadOnlyReplicaDirectoryServer []string `xml:"ReadOnlyReplicaDirectoryServer>string"`
	ReplicaDirectoryServer         []string `xml:"ReplicaDirectoryServer>string"`
	SubordinateReferences          []string `xml:"SubordinateReferences>string"`
}

// ADCAPActiveDirectoryDomain is the decoded subset of MS-ADCAP ActiveDirectoryDomain.
type ADCAPActiveDirectoryDomain struct {
	ADCAPActiveDirectoryPartition
	AllowedDNSSuffixes                 []string `xml:"AllowedDNSSuffixes>string"`
	AppliedGroupPolicies               []string `xml:"AppliedGroupPolicies>string"`
	ChildDomains                       []string `xml:"ChildDomains>string"`
	ComputersContainer                 string   `xml:"ComputersContainer"`
	DomainControllersContainer         string   `xml:"DomainControllersContainer"`
	DomainMode                         int      `xml:"DomainMode"`
	DomainSID                          string   `xml:"DomainSID"`
	ForeignSecurityPrincipalsContainer string   `xml:"ForeignSecurityPrincipalsContainer"`
	Forest                             string   `xml:"Forest"`
	InfrastructureMaster               string   `xml:"InfrastructureMaster"`
	LastLogonReplicationInterval       string   `xml:"LastLogonReplicationInterval"`
	ManagedBy                          string   `xml:"ManagedBy"`
	NetBIOSName                        string   `xml:"NetBIOSName"`
	PDCEmulator                        string   `xml:"PDCEmulator"`
	ParentDomain                       string   `xml:"ParentDomain"`
	RIDMaster                          string   `xml:"RIDMaster"`
	SystemsContainer                   string   `xml:"SystemsContainer"`
	UsersContainer                     string   `xml:"UsersContainer"`
}

// ADCAPActiveDirectoryForest is the decoded subset of MS-ADCAP ActiveDirectoryForest.
type ADCAPActiveDirectoryForest struct {
	ApplicationPartitions []string `xml:"ApplicationPartitions>string"`
	CrossForestReferences []string `xml:"CrossForestReferences>string"`
	DomainNamingMaster    string   `xml:"DomainNamingMaster"`
	Domains               []string `xml:"Domains>string"`
	ForestMode            int      `xml:"ForestMode"`
	GlobalCatalogs        []string `xml:"GlobalCatalogs>string"`
	Name                  string   `xml:"Name"`
	RootDomain            string   `xml:"RootDomain"`
	SPNSuffixes           []string `xml:"SPNSuffixes>string"`
	SchemaMaster          string   `xml:"SchemaMaster"`
	Sites                 []string `xml:"Sites>string"`
	UPNSuffixes           []string `xml:"UPNSuffixes>string"`
}

// ADCAPVersionInfo is the parsed result of MS-ADCAP GetVersion.
type ADCAPVersionInfo struct {
	Major  int
	Minor  int
	String string
}

type changeOptionalFeatureEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ChangeOptionalFeatureResponse *struct{} `xml:"ChangeOptionalFeatureResponse"`
		Fault                         *Fault    `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getVersionEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetVersionResponse *getVersionResponseXML `xml:"GetVersionResponse"`
		Fault              *Fault                 `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getADForestEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetADForestResponse *getADForestResponseXML `xml:"GetADForestResponse"`
		Fault               *Fault                  `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getADDomainEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetADDomainResponse *getADDomainResponseXML `xml:"GetADDomainResponse"`
		Fault               *Fault                  `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getADDomainControllerEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		GetADDomainControllerResponse *getADDomainControllerResponseXML `xml:"GetADDomainControllerResponse"`
		Fault                         *Fault                            `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

type getVersionResponseXML struct {
	VersionMajor  int    `xml:"VersionMajor"`
	VersionMinor  int    `xml:"VersionMinor"`
	VersionString string `xml:"VersionString"`
}

type getADDomainResponseXML struct {
	Domain *ADCAPActiveDirectoryDomain `xml:"Domain"`
}

type getADForestResponseXML struct {
	Forest *ADCAPActiveDirectoryForest `xml:"Forest"`
}

type ADCAPActiveDirectoryDomainController struct {
	DefaultPartition     string   `xml:"DefaultPartition"`
	HostName             string   `xml:"HostName"`
	InvocationId         string   `xml:"InvocationId"`
	LdapPort             int      `xml:"LdapPort"`
	NTDSSettingsObjectDN string   `xml:"NTDSSettingsObjectDN"`
	Name                 string   `xml:"Name"`
	Partitions           []string `xml:"Partitions>string"`
	ServerObjectDN       string   `xml:"ServerObjectDN"`
	ServerObjectGuid     string   `xml:"ServerObjectGuid"`
	Site                 string   `xml:"Site"`
	SslPort              int      `xml:"SslPort"`
}

type arrayOfActiveDirectoryDomainControllerXML struct {
	Items []ADCAPActiveDirectoryDomainController `xml:"ActiveDirectoryDomainController"`
}

type getADDomainControllerResponseXML struct {
	DomainControllers *arrayOfActiveDirectoryDomainControllerXML `xml:"DomainControllers"`
}

func ParseTranslateNameResponse(soapXML string) ([]NameTranslateResult, error) {
	var env translateNameEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.TranslateNameResponse == nil {
		return nil, fmt.Errorf("no TranslateNameResponse in body")
	}
	if env.Body.TranslateNameResponse.NameTranslateResult == nil {
		return []NameTranslateResult{}, nil
	}

	out := make([]NameTranslateResult, 0, len(env.Body.TranslateNameResponse.NameTranslateResult.Results))
	for _, r := range env.Body.TranslateNameResponse.NameTranslateResult.Results {
		out = append(out, NameTranslateResult{Name: r.Name, Result: r.Result})
	}
	return out, nil
}

func ParseGetADGroupMemberResponse(soapXML string) ([]ADCAPActiveDirectoryPrincipal, error) {
	var env getADGroupMemberEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetADGroupMemberResponse == nil {
		return nil, fmt.Errorf("no GetADGroupMemberResponse in body")
	}
	if env.Body.GetADGroupMemberResponse.Members == nil {
		return []ADCAPActiveDirectoryPrincipal{}, nil
	}
	return env.Body.GetADGroupMemberResponse.Members.Items, nil
}

func ParseGetADPrincipalAuthorizationGroupResponse(soapXML string) ([]ADCAPActiveDirectoryGroup, error) {
	var env getADPrincipalAuthorizationGroupEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetADPrincipalAuthorizationGroupResponse == nil {
		return nil, fmt.Errorf("no GetADPrincipalAuthorizationGroupResponse in body")
	}
	if env.Body.GetADPrincipalAuthorizationGroupResponse.MemberOf == nil {
		return []ADCAPActiveDirectoryGroup{}, nil
	}
	return env.Body.GetADPrincipalAuthorizationGroupResponse.MemberOf.Items, nil
}

func ParseGetADPrincipalGroupMembershipResponse(soapXML string) ([]ADCAPActiveDirectoryGroup, error) {
	var env getADPrincipalGroupMembershipEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetADPrincipalGroupMembershipResponse == nil {
		return nil, fmt.Errorf("no GetADPrincipalGroupMembershipResponse in body")
	}
	if env.Body.GetADPrincipalGroupMembershipResponse.MemberOf == nil {
		return []ADCAPActiveDirectoryGroup{}, nil
	}
	return env.Body.GetADPrincipalGroupMembershipResponse.MemberOf.Items, nil
}

func ParseChangeOptionalFeatureResponse(soapXML string) error {
	var env changeOptionalFeatureEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return faultError(env.Body.Fault)
	}
	if env.Body.ChangeOptionalFeatureResponse == nil {
		return fmt.Errorf("no ChangeOptionalFeatureResponse in body")
	}
	return nil
}

func ParseGetVersionResponse(soapXML string) (*ADCAPVersionInfo, error) {
	var env getVersionEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetVersionResponse == nil {
		return nil, fmt.Errorf("no GetVersionResponse in body")
	}
	resp := env.Body.GetVersionResponse
	return &ADCAPVersionInfo{Major: resp.VersionMajor, Minor: resp.VersionMinor, String: resp.VersionString}, nil
}

func ParseGetADForestResponse(soapXML string) (*ADCAPActiveDirectoryForest, error) {
	var env getADForestEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetADForestResponse == nil {
		return nil, fmt.Errorf("no GetADForestResponse in body")
	}
	if env.Body.GetADForestResponse.Forest == nil {
		return &ADCAPActiveDirectoryForest{}, nil
	}
	return env.Body.GetADForestResponse.Forest, nil
}

func ParseGetADDomainResponse(soapXML string) (*ADCAPActiveDirectoryDomain, error) {
	var env getADDomainEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetADDomainResponse == nil {
		return nil, fmt.Errorf("no GetADDomainResponse in body")
	}
	if env.Body.GetADDomainResponse.Domain == nil {
		return &ADCAPActiveDirectoryDomain{}, nil
	}
	return env.Body.GetADDomainResponse.Domain, nil
}

func ParseGetADDomainControllerResponse(soapXML string) ([]ADCAPActiveDirectoryDomainController, error) {
	var env getADDomainControllerEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if env.Body.Fault != nil {
		return nil, faultError(env.Body.Fault)
	}
	if env.Body.GetADDomainControllerResponse == nil {
		return nil, fmt.Errorf("no GetADDomainControllerResponse in body")
	}
	resp := env.Body.GetADDomainControllerResponse
	if resp.DomainControllers == nil {
		return []ADCAPActiveDirectoryDomainController{}, nil
	}
	return resp.DomainControllers.Items, nil
}
