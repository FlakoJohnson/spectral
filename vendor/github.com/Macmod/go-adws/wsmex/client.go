// Package wsmex implements a client for the ADWS WS-MetadataExchange (MEX) endpoint.
//
// The MEX endpoint (Windows/MEX) is unauthenticated: it accepts a WS-Transfer Get
// with anonymous credentials and ProtectionNone, and returns the service's WSDL
// and policy metadata as a SOAP response containing wsx:Metadata sections.
package wsmex

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/Macmod/go-adws/soap"
	"github.com/Macmod/go-adws/wsenum"
)

// EndpointMEX is the ADWS metadata exchange endpoint path.
// Per MS-ADDM §2.1, the MEX endpoint is unauthenticated and listens at
// net.tcp://<host>:9389/ActiveDirectoryWebServices/mex
const EndpointMEX = "mex"

// SOAPTransport is the underlying send/receive interface (implemented by NMFConnection).
type SOAPTransport interface {
	Send(soapMessage string) error
	Recv() (string, error)
}

// WSMexClient is a client for the ADWS MEX endpoint.
type WSMexClient struct {
	transport SOAPTransport
	fqdn      string
	port      int
	debugXML  func(label, payload string)
}

// NewWSMexClient creates a new MEX client over the given transport.
func NewWSMexClient(transport SOAPTransport, fqdn string, port int, debugXML func(string, string)) *WSMexClient {
	return &WSMexClient{
		transport: transport,
		fqdn:      fqdn,
		port:      port,
		debugXML:  debugXML,
	}
}

// GetMetadata sends a WS-MetadataExchange Get request and returns the parsed service metadata.
func (c *WSMexClient) GetMetadata() (*ADWSMetadata, error) {
	req := soap.BuildMexGetRequest()
	respXML, err := c.sendAndRecv(req, "WSMexGetMetadata")
	if err != nil {
		return nil, fmt.Errorf("MEX GetMetadata: %w", err)
	}
	if err := soap.ParseFaultIfPresent(respXML); err != nil {
		return nil, err
	}
	return ParseMexResponse(respXML)
}

func (c *WSMexClient) sendAndRecv(soapMessage, label string) (string, error) {
	soapMessage = wsenum.NormalizeSOAPAddressing(soapMessage, c.fqdn, c.port, EndpointMEX)

	if c.debugXML != nil {
		c.debugXML(label+"Request", soapMessage)
	}

	if err := c.transport.Send(soapMessage); err != nil {
		return "", fmt.Errorf("failed to send MEX request: %w", err)
	}

	respXML, err := c.transport.Recv()
	if err != nil {
		return "", fmt.Errorf("failed to receive MEX response: %w", err)
	}
	respXML = strings.TrimSpace(respXML)

	if c.debugXML != nil {
		c.debugXML(label+"Response", respXML)
	}
	return respXML, nil
}

// ADWSEndpoint describes a single ADWS service endpoint advertised by the MEX response.
type ADWSEndpoint struct {
	// Name is the WSDL port name, e.g. "NetTcpBinding_Resource".
	Name string
	// Address is the full net.tcp:// service URL (uses "localhost" as the host name
	// in the raw MEX response; callers should substitute the real DC address as needed).
	Address string
	// AuthType is "Windows" (Kerberos/negotiate) or "UserName" (username+password).
	AuthType string
	// Identity is the Kerberos SPN (Windows auth) or DNS host name (UserName auth).
	Identity string
}

// ADWSMetadata contains the parsed service metadata from the ADWS MEX endpoint.
type ADWSMetadata struct {
	Endpoints []ADWSEndpoint
}

// ParseMexResponse parses the raw SOAP response XML returned by the MEX endpoint
// and returns the service endpoints described in the embedded WSDL sections.
func ParseMexResponse(soapXML string) (*ADWSMetadata, error) {
	var env xmlEnvelope
	if err := xml.Unmarshal([]byte(soapXML), &env); err != nil {
		return nil, fmt.Errorf("parse MEX response: %w", err)
	}

	const wsdlDialect = "http://schemas.xmlsoap.org/wsdl/"

	meta := &ADWSMetadata{}
	for _, section := range env.Body.Metadata.Sections {
		if section.Dialect != wsdlDialect {
			continue
		}
		for _, svc := range section.Definitions.Services {
			for _, port := range svc.Ports {
				ep := ADWSEndpoint{
					Name:    port.Name,
					Address: port.Address.Location,
				}
				switch {
				case port.EPR.Identity.SPN != "":
					ep.AuthType = "Windows"
					ep.Identity = port.EPR.Identity.SPN
				case port.EPR.Identity.DNS != "":
					ep.AuthType = "UserName"
					ep.Identity = port.EPR.Identity.DNS
				default:
					// Derive from the address path as a fallback.
					if strings.Contains(ep.Address, "/Windows/") {
						ep.AuthType = "Windows"
					} else if strings.Contains(ep.Address, "/UserName/") {
						ep.AuthType = "UserName"
					}
				}
				meta.Endpoints = append(meta.Endpoints, ep)
			}
		}
	}

	return meta, nil
}

// -- internal XML types -------------------------------------------------------

type xmlEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    xmlBody  `xml:"Body"`
}

type xmlBody struct {
	Metadata xmlMetadata `xml:"Metadata"`
}

type xmlMetadata struct {
	Sections []xmlMetadataSection `xml:"MetadataSection"`
}

type xmlMetadataSection struct {
	Dialect     string         `xml:"Dialect,attr"`
	Identifier  string         `xml:"Identifier,attr"`
	Definitions xmlDefinitions `xml:"definitions"`
}

type xmlDefinitions struct {
	Services []xmlService `xml:"service"`
}

type xmlService struct {
	Name  string    `xml:"name,attr"`
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Name    string     `xml:"name,attr"`
	Binding string     `xml:"binding,attr"`
	Address xmlAddress `xml:"address"`
	EPR     xmlEPR     `xml:"EndpointReference"`
}

// xmlAddress captures <soap12:address location="..."/>.
type xmlAddress struct {
	Location string `xml:"location,attr"`
}

// xmlEPR captures <wsa10:EndpointReference>.
type xmlEPR struct {
	Address  string      `xml:"Address"`
	Identity xmlIdentity `xml:"Identity"`
}

// xmlIdentity captures <Identity><Spn>…</Spn></Identity> or <Identity><Dns>…</Dns></Identity>.
type xmlIdentity struct {
	SPN string `xml:"Spn"`
	DNS string `xml:"Dns"`
}
