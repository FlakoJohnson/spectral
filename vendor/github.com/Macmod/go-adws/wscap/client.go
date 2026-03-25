package wscap

import (
	"fmt"
	"strings"

	"github.com/Macmod/go-adws/soap"
	"github.com/Macmod/go-adws/wsenum"
)

const (
	EndpointAccountManagement  = "Windows/AccountManagement"
	EndpointTopologyManagement = "Windows/TopologyManagement"
)

type SOAPTransport interface {
	Send(soapMessage string) error
	Recv() (string, error)
}

// WSCapClient is a client for MS-ADCAP (Active Directory Web Services Custom Actions Protocol)
// endpoints (e.g. AccountManagement, TopologyManagement).
//
// Note: the underlying transport must already be connected to the intended endpoint via NMF.
// The endpoint value here is used to normalize WS-Addressing headers (To/Action routing).
type WSCapClient struct {
	transport SOAPTransport
	fqdn      string
	port      int
	endpoint  string
	ldapPort  int
	debugXML  func(label, payload string)
}

// NewWSCapClient creates a WSCapClient targeting endpoint (e.g. EndpointAccountManagement
// or EndpointTopologyManagement). ldapPort controls the ad:instance SOAP header value.
func NewWSCapClient(transport SOAPTransport, fqdn string, port int, endpoint string, ldapPort int, debugXML func(string, string)) *WSCapClient {
	return &WSCapClient{
		transport: transport,
		fqdn:      fqdn,
		port:      port,
		endpoint:  strings.TrimSpace(endpoint),
		ldapPort:  ldapPort,
		debugXML:  debugXML,
	}
}

// SetPassword sets the password for the account at accountDN (MS-ADCAP §3.3.4.5).
// partitionDN is the directory partition containing the account.
func (c *WSCapClient) SetPassword(accountDN, partitionDN, newPassword string) error {
	req, err := soap.BuildSetPasswordRequest(accountDN, partitionDN, newPassword, c.ldapPort)
	if err != nil {
		return err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPSetPasswordResponse")
	if err != nil {
		return fmt.Errorf("set password request failed: %w", err)
	}
	return soap.ParseFaultIfPresent(respXML)
}

// ChangePassword changes the password for the account at accountDN (MS-ADCAP §3.3.4.1).
// The caller must supply the current password as oldPassword.
func (c *WSCapClient) ChangePassword(accountDN, partitionDN, oldPassword, newPassword string) error {
	req, err := soap.BuildChangePasswordRequest(accountDN, partitionDN, oldPassword, newPassword, c.ldapPort)
	if err != nil {
		return err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPChangePasswordResponse")
	if err != nil {
		return fmt.Errorf("change password request failed: %w", err)
	}
	return soap.ParseFaultIfPresent(respXML)
}

// TranslateName translates one or more AD names between the formats specified by
// formatOffered and formatDesired (MS-ADCAP §3.3.4.6). Valid format strings are
// defined in the ActiveDirectoryNameFormat enum (e.g. "DistinguishedName", "CanonicalName").
func (c *WSCapClient) TranslateName(formatOffered, formatDesired string, names []string) ([]soap.NameTranslateResult, error) {
	req, err := soap.BuildTranslateNameRequest(formatOffered, formatDesired, names, c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPTranslateNameResponse")
	if err != nil {
		return nil, fmt.Errorf("translate name request failed: %w", err)
	}
	return soap.ParseTranslateNameResponse(respXML)
}

// GetADGroupMember returns the members of the group at groupDN (MS-ADCAP §3.3.4.2).
// When recursive is true, nested group members are expanded.
func (c *WSCapClient) GetADGroupMember(groupDN, partitionDN string, recursive bool) ([]soap.ADCAPActiveDirectoryPrincipal, error) {
	req, err := soap.BuildGetADGroupMemberRequest(groupDN, partitionDN, recursive, c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetADGroupMemberResponse")
	if err != nil {
		return nil, fmt.Errorf("GetADGroupMember request failed: %w", err)
	}
	return soap.ParseGetADGroupMemberResponse(respXML)
}

// GetADPrincipalAuthorizationGroup returns the authorization groups (security groups
// and SID history) for the principal at principalDN (MS-ADCAP §3.3.4.3).
func (c *WSCapClient) GetADPrincipalAuthorizationGroup(partitionDN, principalDN string) ([]soap.ADCAPActiveDirectoryGroup, error) {
	req, err := soap.BuildGetADPrincipalAuthorizationGroupRequest(partitionDN, principalDN, c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetADPrincipalAuthorizationGroupResponse")
	if err != nil {
		return nil, fmt.Errorf("GetADPrincipalAuthorizationGroup request failed: %w", err)
	}
	return soap.ParseGetADPrincipalAuthorizationGroupResponse(respXML)
}

// GetADPrincipalGroupMembership returns the group memberships of the principal at
// principalDN (MS-ADCAP §3.3.4.4). resourceContextPartition and resourceContextServer
// must both be set or both be empty.
func (c *WSCapClient) GetADPrincipalGroupMembership(partitionDN, principalDN, resourceContextPartition, resourceContextServer string) ([]soap.ADCAPActiveDirectoryGroup, error) {
	req, err := soap.BuildGetADPrincipalGroupMembershipRequest(partitionDN, principalDN, resourceContextPartition, resourceContextServer, c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetADPrincipalGroupMembershipResponse")
	if err != nil {
		return nil, fmt.Errorf("GetADPrincipalGroupMembership request failed: %w", err)
	}
	return soap.ParseGetADPrincipalGroupMembershipResponse(respXML)
}

// ChangeOptionalFeature enables or disables the AD optional feature identified by featureID
// (a well-formed GUID string) on the scope object at distinguishedName (MS-ADCAP §3.4.4.1).
func (c *WSCapClient) ChangeOptionalFeature(distinguishedName string, enable bool, featureID string) error {
	req, err := soap.BuildChangeOptionalFeatureRequest(distinguishedName, enable, featureID, c.ldapPort)
	if err != nil {
		return err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPChangeOptionalFeatureResponse")
	if err != nil {
		return fmt.Errorf("change optional feature request failed: %w", err)
	}
	return soap.ParseChangeOptionalFeatureResponse(respXML)
}

// GetADDomain returns domain properties from the TopologyManagement endpoint (MS-ADCAP §3.4.4.2).
func (c *WSCapClient) GetADDomain() (*soap.ADCAPActiveDirectoryDomain, error) {
	req, err := soap.BuildGetADDomainRequest(c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetADDomainResponse")
	if err != nil {
		return nil, fmt.Errorf("get AD domain request failed: %w", err)
	}
	return soap.ParseGetADDomainResponse(respXML)
}

// GetADForest returns forest properties from the TopologyManagement endpoint (MS-ADCAP §3.4.4.4).
func (c *WSCapClient) GetADForest() (*soap.ADCAPActiveDirectoryForest, error) {
	req, err := soap.BuildGetADForestRequest(c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetADForestResponse")
	if err != nil {
		return nil, fmt.Errorf("get AD forest request failed: %w", err)
	}
	return soap.ParseGetADForestResponse(respXML)
}

// GetVersion returns the ADWS server version from the TopologyManagement endpoint (MS-ADCAP §3.4.4.5).
func (c *WSCapClient) GetVersion() (*soap.ADCAPVersionInfo, error) {
	req, err := soap.BuildGetVersionRequest(c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetVersionResponse")
	if err != nil {
		return nil, fmt.Errorf("get version request failed: %w", err)
	}
	return soap.ParseGetVersionResponse(respXML)
}

// GetADDomainController returns information about domain controllers whose NTDS settings
// objects match the given DNs (MS-ADCAP §3.4.4.3). Pass nil or an empty slice to query
// the DC serving the connection.
func (c *WSCapClient) GetADDomainController(ntdsSettingsDNs []string) ([]soap.ADCAPActiveDirectoryDomainController, error) {
	req, err := soap.BuildGetADDomainControllerRequest(ntdsSettingsDNs, c.ldapPort)
	if err != nil {
		return nil, err
	}

	respXML, err := c.sendAndRecv(req, "ADCAPGetADDomainControllerResponse")
	if err != nil {
		return nil, fmt.Errorf("get AD domain controller request failed: %w", err)
	}
	return soap.ParseGetADDomainControllerResponse(respXML)
}

func (c *WSCapClient) sendAndRecv(soapMessage, debugLabel string) (string, error) {
	if c == nil || c.transport == nil {
		return "", fmt.Errorf("transport is not initialized")
	}
	soapMessage = wsenum.NormalizeSOAPAddressing(soapMessage, c.fqdn, c.port, c.endpoint)

	if c.debugXML != nil {
		reqLabel := strings.TrimSpace(debugLabel)
		if strings.HasSuffix(reqLabel, "Response") {
			reqLabel = strings.TrimSuffix(reqLabel, "Response") + "Request"
		} else {
			reqLabel = reqLabel + "Request"
		}
		c.debugXML(reqLabel, soapMessage)
	}

	if err := c.transport.Send(soapMessage); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	respXML, err := c.transport.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive response: %w", err)
	}
	respXML = strings.TrimSpace(respXML)

	if c.debugXML != nil {
		c.debugXML(debugLabel, respXML)
	}
	return respXML, nil
}
