package wsenum

import (
	"fmt"
	"strings"

	soap "github.com/Macmod/go-adws/soap"
)

const EndpointEnumeration = "Windows/Enumeration"

type SOAPTransport interface {
	Send(soapMessage string) error
	Recv() (string, error)
}

// WSEnumClient sends WS-Enumeration requests over an authenticated NMF transport to the
// Windows/Enumeration endpoint. Callers typically use ExecuteQuery (executor.go) rather
// than calling Enumerate and Pull directly.
type WSEnumClient struct {
	transport SOAPTransport
	fqdn      string
	port      int
	ldapPort  int
	debugXML  func(label, payload string)
	debugPull func(*soap.PullResponse)
}

// NewWSEnumClient creates a WSEnumClient. debugXML, if non-nil, is called with the
// request/response label and raw SOAP XML for every exchange. debugPull, if non-nil,
// is called with the parsed PullResponse after each Pull.
func NewWSEnumClient(transport SOAPTransport, fqdn string, port int, ldapPort int, debugXML func(string, string), debugPull func(*soap.PullResponse)) *WSEnumClient {
	return &WSEnumClient{
		transport: transport,
		fqdn:      fqdn,
		port:      port,
		ldapPort:  ldapPort,
		debugXML:  debugXML,
		debugPull: debugPull,
	}
}

// Enumerate opens an enumeration context for the given LDAP query.
// scope: 0=Base, 1=OneLevel, 2=Subtree.
func (ws *WSEnumClient) Enumerate(baseDN, filter string, attrs []string, scope int) (*soap.EnumerateResponse, error) {
	req := soap.BuildEnumerateRequest(baseDN, filter, attrs, scope, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSEnumEnumerate", req)
	if err != nil {
		return nil, fmt.Errorf("enumerate request failed: %w", err)
	}

	resp, err := soap.ParseEnumerateResponse(respXML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EnumerateResponse: %w", err)
	}
	return resp, nil
}

// Pull retrieves the next page of results from an open enumeration context.
// sdFlags, when non-zero, encodes an LDAP_SERVER_SD_FLAGS_OID control into the request.
func (ws *WSEnumClient) Pull(enumerationContext string, maxElements int, sdFlags int) (*soap.PullResponse, error) {
	enumerationContext = strings.TrimSpace(enumerationContext)
	if enumerationContext == "" {
		return nil, fmt.Errorf("enumerationContext is required")
	}

	req := soap.BuildPullRequest(enumerationContext, maxElements, ws.ldapPort, sdFlags)
	respXML, err := ws.sendAndRecv("WSEnumPull", req)
	if err != nil {
		return nil, fmt.Errorf("pull request failed: %w", err)
	}

	resp, err := soap.ParsePullResponse(respXML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PullResponse: %w", err)
	}

	if ws.debugPull != nil {
		ws.debugPull(resp)
	}
	return resp, nil
}

// GetStatus queries the expiry time of an open enumeration context.
func (ws *WSEnumClient) GetStatus(enumerationContext string) (*soap.GetStatusResponse, error) {
	enumerationContext = strings.TrimSpace(enumerationContext)
	if enumerationContext == "" {
		return nil, fmt.Errorf("enumerationContext is required")
	}

	req := soap.BuildGetStatusRequest(enumerationContext, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSEnumGetStatus", req)
	if err != nil {
		return nil, fmt.Errorf("getstatus request failed: %w", err)
	}
	return soap.ParseGetStatusResponse(respXML)
}

// Renew extends the lifetime of an open enumeration context. expires is an xsd:dateTime
// string (e.g. "PT120S" for 120 seconds); an empty string requests the server default.
func (ws *WSEnumClient) Renew(enumerationContext, expires string) (*soap.RenewResponse, error) {
	enumerationContext = strings.TrimSpace(enumerationContext)
	if enumerationContext == "" {
		return nil, fmt.Errorf("enumerationContext is required")
	}

	req := soap.BuildRenewRequest(enumerationContext, expires, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSEnumRenew", req)
	if err != nil {
		return nil, fmt.Errorf("renew request failed: %w", err)
	}
	return soap.ParseRenewResponse(respXML)
}

// Release terminates an open enumeration context, freeing server-side resources.
func (ws *WSEnumClient) Release(enumerationContext string) error {
	enumerationContext = strings.TrimSpace(enumerationContext)
	if enumerationContext == "" {
		return fmt.Errorf("enumerationContext is required")
	}

	req := soap.BuildReleaseRequest(enumerationContext, ws.ldapPort)
	respXML, err := ws.sendAndRecv("WSEnumRelease", req)
	if err != nil {
		return fmt.Errorf("release request failed: %w", err)
	}
	return soap.ParseReleaseResponse(respXML)
}

func (ws *WSEnumClient) sendAndRecv(label string, soapMessage string) (string, error) {
	soapMessage = NormalizeSOAPAddressing(soapMessage, ws.fqdn, ws.port, EndpointEnumeration)
	if ws.debugXML != nil {
		ws.debugXML(label+"Request", soapMessage)
	}

	if err := ws.transport.Send(soapMessage); err != nil {
		return "", fmt.Errorf("failed to send WS-Enumeration request: %w", err)
	}

	respXML, err := ws.transport.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive WS-Enumeration response: %w", err)
	}

	if ws.debugXML != nil {
		ws.debugXML(label+"Response", respXML)
	}
	return respXML, nil
}

// NormalizeSOAPAddressing replaces the sentinel wsa:To URI
// ("http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/Instance") with the
// actual net.tcp endpoint URI for the target DC. Called by all client packages before
// sending, keeping SOAP builders transport-agnostic.
func NormalizeSOAPAddressing(soapMessage, fqdn string, port int, endpoint string) string {
	to := fmt.Sprintf("net.tcp://%s:%d/ActiveDirectoryWebServices/%s", fqdn, port, endpoint)
	return strings.ReplaceAll(soapMessage,
		"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/Instance",
		to,
	)
}
