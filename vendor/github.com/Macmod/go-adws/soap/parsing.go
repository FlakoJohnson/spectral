package soap

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

type EnumerateResponse struct {
	EnumerationContext string
	EndOfSequence      bool
}

type PullResponse struct {
	Items              []ADWSItem
	EnumerationContext string
	EndOfSequence      bool
}

type GetStatusResponse struct {
	Expires string
}

type RenewResponse struct {
	Expires string
}

type ADWSItem struct {
	ObjectGUID        string
	DistinguishedName string
	Attributes        map[string][]ADWSValue
}

type ADWSValue struct {
	Value      string
	LdapSyntax string
	RawValue   []byte
}

func ParseEnumerateResponse(soapXML string) (*EnumerateResponse, error) {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return nil, faultError(envelope.Body.Fault)
	}
	if envelope.Body.EnumerateResponse == nil {
		return nil, fmt.Errorf("no EnumerateResponse in body")
	}
	return &EnumerateResponse{EnumerationContext: envelope.Body.EnumerateResponse.EnumerationContext, EndOfSequence: envelope.Body.EnumerateResponse.EndOfSequence}, nil
}

func ParsePullResponse(soapXML string) (*PullResponse, error) {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return nil, faultError(envelope.Body.Fault)
	}
	if envelope.Body.PullResponse == nil {
		return nil, fmt.Errorf("no PullResponse in body")
	}

	pr := envelope.Body.PullResponse
	result := &PullResponse{EnumerationContext: pr.EnumerationContext, EndOfSequence: pr.EndOfSequence != nil, Items: make([]ADWSItem, 0, len(pr.Items.Objects))}
	for _, obj := range pr.Items.Objects {
		item := ADWSItem{Attributes: make(map[string][]ADWSValue)}
		for _, field := range obj.Fields {
			fieldName := field.XMLName.Local
			if strings.EqualFold(fieldName, "objectReferenceProperty") {
				if len(field.Values) > 0 && item.ObjectGUID == "" {
					item.ObjectGUID = strings.TrimSpace(field.Values[0].Content)
				}
				continue
			}

			values := make([]ADWSValue, 0, len(field.Values))
			for _, val := range field.Values {
				v := val.Content
				if field.LdapSyntax == "OctetString" {
					v = strings.TrimSpace(v)
				}
				adwsVal := ADWSValue{Value: v, LdapSyntax: field.LdapSyntax}
				if field.LdapSyntax == "OctetString" && adwsVal.Value != "" {
					decodedStr, rawBytes, err := decodeBinaryAttribute(fieldName, adwsVal.Value)
					if err == nil {
						adwsVal.Value = decodedStr
						adwsVal.RawValue = rawBytes
					}
				}
				values = append(values, adwsVal)
			}
			if len(values) == 0 {
				continue
			}
			item.Attributes[fieldName] = values
			if strings.EqualFold(fieldName, "distinguishedName") && item.DistinguishedName == "" {
				item.DistinguishedName = values[0].Value
			}
			if strings.EqualFold(fieldName, "objectGUID") {
				item.ObjectGUID = values[0].Value
			}
		}
		result.Items = append(result.Items, item)
	}
	return result, nil
}

// ParseBaseObjectSearchResponse parses a WS-Transfer Get response as returned by the
// ADWS Windows/Resource endpoint.
//
// The response body is typically:
//   <da:BaseObjectSearchResponse>
//     <da:PartialAttribute>
//       <addata:cn LdapSyntax="UnicodeString"><ad:value ...>...</ad:value></addata:cn>
//     </da:PartialAttribute>
//     ...
//   </da:BaseObjectSearchResponse>
func ParseBaseObjectSearchResponse(soapXML string) (*ADWSItem, error) {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return nil, faultError(envelope.Body.Fault)
	}
	if envelope.Body.BaseObjectSearchResponse == nil {
		return nil, fmt.Errorf("no BaseObjectSearchResponse in body")
	}

	item := &ADWSItem{Attributes: make(map[string][]ADWSValue)}
	for _, partial := range envelope.Body.BaseObjectSearchResponse.PartialAttributes {
		for _, field := range partial.Fields {
			fieldName := field.XMLName.Local
			if strings.EqualFold(fieldName, "objectReferenceProperty") {
				continue
			}

			values := make([]ADWSValue, 0, len(field.Values))
			for _, val := range field.Values {
				v := val.Content
				if field.LdapSyntax == "OctetString" {
					v = strings.TrimSpace(v)
				}
				adwsVal := ADWSValue{Value: v, LdapSyntax: field.LdapSyntax}
				if field.LdapSyntax == "OctetString" && adwsVal.Value != "" {
					decodedStr, rawBytes, err := decodeBinaryAttribute(fieldName, adwsVal.Value)
					if err == nil {
						adwsVal.Value = decodedStr
						adwsVal.RawValue = rawBytes
					}
				}
				values = append(values, adwsVal)
			}
			if len(values) == 0 {
				continue
			}
			item.Attributes[fieldName] = values
			if strings.EqualFold(fieldName, "distinguishedName") && item.DistinguishedName == "" {
				item.DistinguishedName = values[0].Value
			}
			if strings.EqualFold(fieldName, "objectGUID") {
				item.ObjectGUID = values[0].Value
			}
		}
	}

	return item, nil
}

// ParseWSTransferCreateAddress extracts the created resource address/object reference from a
// WS-Transfer CreateResponse.
//
// ADWS may surface the created resource as either:
//   - <wst:ResourceCreated><wsa:Address>...</wsa:Address></wst:ResourceCreated>
//   - or an AD-specific <ad:objectReferenceProperty>...</ad:objectReferenceProperty>
//
// This function is best-effort: it returns the first matching value found.
func ParseWSTransferCreateAddress(soapXML string) (string, error) {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return "", fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return "", faultError(envelope.Body.Fault)
	}
	if envelope.Body.CreateResponse == nil {
		return "", fmt.Errorf("no CreateResponse in body")
	}

	cr := envelope.Body.CreateResponse
	if cr.ResourceCreated != nil {
		addr := strings.TrimSpace(cr.ResourceCreated.Address)
		if addr != "" {
			return addr, nil
		}
	}
	if cr.ObjectReferenceProperty != nil {
		if len(cr.ObjectReferenceProperty.Values) > 0 {
			v := strings.TrimSpace(cr.ObjectReferenceProperty.Values[0].Content)
			if v != "" {
				return v, nil
			}
		}
		v := strings.TrimSpace(cr.ObjectReferenceProperty.Content)
		if v != "" {
			return v, nil
		}
	}

	return "", fmt.Errorf("no created resource address/object reference found in CreateResponse")
}

func ParseGetStatusResponse(soapXML string) (*GetStatusResponse, error) {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return nil, faultError(envelope.Body.Fault)
	}
	r := &GetStatusResponse{}
	if envelope.Body.GetStatusResponse != nil {
		r.Expires = envelope.Body.GetStatusResponse.Expires
	}
	return r, nil
}

func ParseRenewResponse(soapXML string) (*RenewResponse, error) {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return nil, faultError(envelope.Body.Fault)
	}
	r := &RenewResponse{}
	if envelope.Body.RenewResponse != nil {
		r.Expires = envelope.Body.RenewResponse.Expires
	}
	return r, nil
}

func ParseReleaseResponse(soapXML string) error {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault != nil {
		return faultError(envelope.Body.Fault)
	}
	return nil
}

func ParseFaultIfPresent(soapXML string) error {
	var envelope Envelope
	if err := xml.Unmarshal([]byte(soapXML), &envelope); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}
	if envelope.Body.Fault == nil {
		return nil
	}
	return faultError(envelope.Body.Fault)
}

func faultError(f *Fault) error {
	// Per SOAP 1.2 / MS-WSDS / MS-ADCAP: Code/Value is always the generic
	// soapenv:Sender or soapenv:Receiver. The meaningful identifier lives in
	// Code/Subcode/Value (e.g. "ad:EnumerationContextLimitExceeded",
	// "ChangePasswordFault", "wsa2004:EndPointUnavailable").
	code := strings.TrimSpace(f.Code.Value)
	subcode := ""
	if f.Code.Subcode != nil {
		subcode = strings.TrimSpace(f.Code.Subcode.Value)
	}
	reason := strings.TrimSpace(f.Reason.Text)
	inner := ""
	if f.Detail != nil {
		inner = strings.TrimSpace(f.Detail.Inner)
	}

	// Build the displayed code: prefer subcode (specific), fall back to code (generic).
	displayCode := subcode
	if displayCode == "" {
		displayCode = code
	}

	// Try to extract the common DirectoryError payload for MS-ADCAP faults.
	// This is best-effort: if it doesn't match, fall back to the raw detail XML.
	if inner != "" {
		type directoryError struct {
			ErrorCode            int    `xml:"ErrorCode"`
			Win32ErrorCode       int    `xml:"Win32ErrorCode"`
			Message              string `xml:"Message"`
			ShortMessage         string `xml:"ShortMessage"`
			ExtendedErrorMessage string `xml:"ExtendedErrorMessage"`
		}

		extractDirectoryError := func(detailInner string) *directoryError {
			dec := xml.NewDecoder(strings.NewReader(detailInner))
			for {
				tok, err := dec.Token()
				if err != nil {
					if err == io.EOF {
						return nil
					}
					return nil
				}
				se, ok := tok.(xml.StartElement)
				if !ok {
					continue
				}
				if strings.EqualFold(se.Name.Local, "DirectoryError") {
					var de directoryError
					if err := dec.DecodeElement(&de, &se); err == nil {
						return &de
					}
					return nil
				}
			}
		}

		if de := extractDirectoryError(inner); de != nil {
			parts := []string{}
			if de.ShortMessage != "" {
				parts = append(parts, strings.TrimSpace(de.ShortMessage))
			}
			if de.Message != "" {
				parts = append(parts, strings.TrimSpace(de.Message))
			}
			if de.ErrorCode != 0 {
				parts = append(parts, fmt.Sprintf("ErrorCode=%d", de.ErrorCode))
			}
			if de.Win32ErrorCode != 0 {
				parts = append(parts, fmt.Sprintf("Win32=%d", de.Win32ErrorCode))
			}
			if eem := strings.TrimSpace(de.ExtendedErrorMessage); eem != "" {
				parts = append(parts, eem)
			}

			// Common AD DS password-change failures surface as:
			//   ErrorCode=19 / Win32=8239 and ExtendedErrorMessage mentions unicodePwd.
			// In a default AD domain policy, minimum password age and password history can trigger this.
			hint := ""
			eemLower := strings.ToLower(de.ExtendedErrorMessage)
			if de.ErrorCode == 19 && (de.Win32ErrorCode == 8239 || strings.Contains(eemLower, "unicodepwd")) {
				hint = "hint: for ChangePassword this usually means old password mismatch OR password policy/constraints (e.g. minimum password age, history, complexity). SetPassword can still succeed because it's a reset."
			}

			if len(parts) > 0 {
				if hint != "" {
					return fmt.Errorf("SOAP Fault [%s]: %s (%s)\n%s", displayCode, reason, strings.Join(parts, "; "), hint)
				}
				return fmt.Errorf("SOAP Fault [%s]: %s (%s)", displayCode, reason, strings.Join(parts, "; "))
			}
		}

		return fmt.Errorf("SOAP Fault [%s]: %s - %s", displayCode, reason, inner)
	}

	return fmt.Errorf("SOAP Fault [%s]: %s", displayCode, reason)
}

type Envelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  Header   `xml:"Header"`
	Body    Body     `xml:"Body"`
}

type Header struct {
	Action    string `xml:"Action"`
	MessageID string `xml:"MessageID"`
	RelatesTo string `xml:"RelatesTo,omitempty"`
}

type Body struct {
	EnumerateResponse        *EnumerateResponseXML        `xml:"EnumerateResponse,omitempty"`
	PullResponse             *PullResponseXML             `xml:"PullResponse,omitempty"`
	GetStatusResponse        *GetStatusResponseXML        `xml:"GetStatusResponse,omitempty"`
	RenewResponse            *RenewResponseXML            `xml:"RenewResponse,omitempty"`
	CreateResponse           *CreateResponseXML           `xml:"CreateResponse,omitempty"`
	BaseObjectSearchResponse *BaseObjectSearchResponseXML `xml:"BaseObjectSearchResponse,omitempty"`
	Fault                    *Fault                       `xml:"Fault,omitempty"`
}

type CreateResponseXML struct {
	ResourceCreated         *ResourceCreatedXML         `xml:"ResourceCreated"`
	ObjectReferenceProperty *ObjectReferencePropertyXML `xml:"objectReferenceProperty"`
}

type ResourceCreatedXML struct {
	Address string `xml:"Address"`
}

type ObjectReferencePropertyXML struct {
	Values  []FieldValue `xml:"value"`
	Content string       `xml:",chardata"`
}

type BaseObjectSearchResponseXML struct {
	PartialAttributes []PartialAttributeXML `xml:"PartialAttribute"`
}

type PartialAttributeXML struct {
	Fields []ObjectField `xml:",any"`
}

type EnumerateResponseXML struct {
	EnumerationContext string `xml:"EnumerationContext"`
	EndOfSequence      bool   `xml:"EndOfSequence,omitempty"`
}

type GetStatusResponseXML struct {
	Expires string `xml:"Expires"`
}

type RenewResponseXML struct {
	Expires string `xml:"Expires"`
}

type PullResponseXML struct {
	EnumerationContext string    `xml:"EnumerationContext"`
	Items              Items     `xml:"Items"`
	EndOfSequence      *struct{} `xml:"EndOfSequence,omitempty"`
}

type Items struct {
	Objects []ObjectEntry `xml:",any"`
}

type ObjectEntry struct {
	XMLName xml.Name      `xml:""`
	Fields  []ObjectField `xml:",any"`
}

type ObjectField struct {
	XMLName    xml.Name     `xml:""`
	LdapSyntax string       `xml:"LdapSyntax,attr"`
	Values     []FieldValue `xml:"value"`
}

type FieldValue struct {
	Content string `xml:",chardata"`
}

type Fault struct {
	Code   FaultCode    `xml:"Code"`
	Reason FaultReason  `xml:"Reason"`
	Detail *FaultDetail `xml:"Detail,omitempty"`
}

type FaultCode struct {
	Value   string        `xml:"Value"`
	Subcode *FaultSubcode `xml:"Subcode,omitempty"`
}

type FaultSubcode struct {
	Value string `xml:"Value"`
}

type FaultReason struct {
	Text string `xml:"Text"`
}

// FaultDetail holds the raw inner XML of a SOAP Fault/Detail element so
// that structured sub-elements (e.g. DirectoryError) can be extracted.
type FaultDetail struct {
	Inner string `xml:",innerxml"`
}
