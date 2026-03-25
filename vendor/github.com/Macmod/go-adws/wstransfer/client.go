package wstransfer

import (
	"fmt"
	"strings"

	soap "github.com/Macmod/go-adws/soap"
	"github.com/Macmod/go-adws/wsenum"
)

const (
	EndpointResource        = "Windows/Resource"
	EndpointResourceFactory = "Windows/ResourceFactory"
)

type SOAPTransport interface {
	Send(soapMessage string) error
	Recv() (string, error)
}

// WSTransferClient sends WS-Transfer requests over an authenticated NMF transport.
// Depending on the operation, it targets either the Windows/Resource endpoint (Get, Put,
// Delete) or Windows/ResourceFactory (Create and Add* helpers).
type WSTransferClient struct {
	transport SOAPTransport
	fqdn      string
	port      int
	endpoint  string
	ldapPort  int
	debugXML  func(label, payload string)
}

// NewWSTransferClient creates a WSTransferClient targeting the given endpoint.
// ldapPort controls the ad:instance header value (389 for a DC, 3268 for a GC).
func NewWSTransferClient(transport SOAPTransport, fqdn string, port int, endpoint string, ldapPort int, debugXML func(string, string)) *WSTransferClient {
	return &WSTransferClient{
		transport: transport,
		fqdn:      fqdn,
		port:      port,
		endpoint:  endpoint,
		ldapPort:  ldapPort,
		debugXML:  debugXML,
	}
}

// Get fetches the specified attributes of a single AD object by distinguished name
// using WS-Transfer Get (Windows/Resource).
func (ws *WSTransferClient) Get(dn string, attrs []string) (*soap.ADWSItem, error) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil, fmt.Errorf("dn is required")
	}

	req := soap.BuildGetRequest(dn, attrs, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSTransferGet", req)
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return nil, err
	}
	return soap.ParseBaseObjectSearchResponse(respXML)
}

// Delete removes the AD object at the given distinguished name using WS-Transfer Delete.
func (ws *WSTransferClient) Delete(dn string) error {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return fmt.Errorf("dn is required")
	}

	req := soap.BuildDeleteRequest(dn, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSTransferDelete", req)
	if err != nil {
		return fmt.Errorf("delete request failed: %w", err)
	}
	return soap.ParseFaultIfPresent(respXML)
}

// Put modifies attributes of an existing AD object using WS-Transfer Put.
// instanceXML is a raw LDAP attribute XML payload (IMDA ModifyRequest body).
func (ws *WSTransferClient) Put(dn, instanceXML string) error {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return fmt.Errorf("dn is required")
	}
	if strings.TrimSpace(instanceXML) == "" {
		return fmt.Errorf("instanceXML is required")
	}

	req := soap.BuildPutRequest(dn, instanceXML, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSTransferPut", req)
	if err != nil {
		return fmt.Errorf("put request failed: %w", err)
	}
	return soap.ParseFaultIfPresent(respXML)
}

// Create executes WS-Transfer Create and returns the address of the created resource.
//
// The address is best-effort and may be empty if the server response does not include a
// parsable ResourceCreated/Address or objectReferenceProperty.
func (ws *WSTransferClient) Create(instanceXML string) (string, error) {
	if strings.TrimSpace(instanceXML) == "" {
		return "", fmt.Errorf("instanceXML is required")
	}

	req := soap.BuildCreateRequest(instanceXML, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSTransferCreate", req)
	if err != nil {
		return "", fmt.Errorf("create request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}

	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// CreateComputer creates a minimal computer object under parentDN. For a fully-configured
// account with a domain name and password, use AddComputer instead.
func (ws *WSTransferClient) CreateComputer(parentDN, computerName string) (string, error) {
	req, err := soap.BuildCreateComputerRequest(parentDN, computerName, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferCreateComputer", req)
	if err != nil {
		return "", fmt.Errorf("create computer request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// AddComputer creates a computer account under parentDN using an IMDA AddRequest.
func (ws *WSTransferClient) AddComputer(parentDN, computerName, domainName, computerPass string) (string, error) {
	req, err := soap.BuildAddComputerRequest(parentDN, computerName, domainName, computerPass, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferAddComputer", req)
	if err != nil {
		return "", fmt.Errorf("add computer request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// AddUser creates a user account under parentDN using an IMDA AddRequest.
func (ws *WSTransferClient) AddUser(parentDN, userName, domainName, userPass string, enabled bool) (string, error) {
	req, err := soap.BuildAddUserRequest(parentDN, userName, domainName, userPass, enabled, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferAddUser", req)
	if err != nil {
		return "", fmt.Errorf("add user request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// AddGroup creates a security or distribution group under parentDN.
// groupType is an AD groupType integer as a decimal string (e.g. "-2147483646" for global security).
func (ws *WSTransferClient) AddGroup(parentDN, groupName, groupType string) (string, error) {
	req, err := soap.BuildAddGroupRequest(parentDN, groupName, groupType, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferAddGroup", req)
	if err != nil {
		return "", fmt.Errorf("add group request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// AddOU creates an organizationalUnit container under parentDN.
func (ws *WSTransferClient) AddOU(parentDN, ouName string) (string, error) {
	req, err := soap.BuildAddOURequest(parentDN, ouName, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferAddOU", req)
	if err != nil {
		return "", fmt.Errorf("add ou request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// AddContainer creates a generic container object under parentDN.
func (ws *WSTransferClient) AddContainer(parentDN, cn string) (string, error) {
	req, err := soap.BuildAddContainerRequest(parentDN, cn, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferAddContainer", req)
	if err != nil {
		return "", fmt.Errorf("add container request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

// CustomCreate creates an arbitrary AD object under parentDN using an IMDA AddRequest
// with a caller-supplied attribute set. rdn is the relative distinguished name (e.g. "CN=Foo").
func (ws *WSTransferClient) CustomCreate(parentDN, rdn string, attrs []soap.IMDAAttributeSpec) (string, error) {
	req, err := soap.BuildAddCustomRequest(parentDN, rdn, attrs, ws.ldapPort)
	if err != nil {
		return "", err
	}

	respXML, err := ws.sendAndRecv("WSTransferCustomCreate", req)
	if err != nil {
		return "", fmt.Errorf("custom create request failed: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return "", err
	}
	addr, _ := soap.ParseWSTransferCreateAddress(respXML)
	return addr, nil
}

func (ws *WSTransferClient) sendAndRecv(label, soapMessage string) (string, error) {
	soapMessage = wsenum.NormalizeSOAPAddressing(soapMessage, ws.fqdn, ws.port, ws.endpoint)
	if ws.debugXML != nil {
		ws.debugXML(label+"Request", soapMessage)
	}

	if err := ws.transport.Send(soapMessage); err != nil {
		return "", fmt.Errorf("failed to send WS-Transfer request: %w", err)
	}

	respXML, err := ws.transport.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive WS-Transfer response: %w", err)
	}

	if ws.debugXML != nil {
		ws.debugXML(label+"Response", respXML)
	}
	return respXML, nil
}
