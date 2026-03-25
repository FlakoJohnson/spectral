package soap

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

const (
	NsSOAP          = "http://www.w3.org/2003/05/soap-envelope"
	NsWSAddr        = "http://www.w3.org/2005/08/addressing"
	NsADData        = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
	NsAD            = "http://schemas.microsoft.com/2008/1/ActiveDirectory"
	NsWSEnum        = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	NsWSTransfer    = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
	NsCustomActions = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions"
)

const (
	ActionEnumerate     = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	ActionEnumerateResp = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse"
	ActionPull          = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
	ActionPullResp      = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/PullResponse"
	ActionGetStatus     = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/GetStatus"
	ActionGetStatusResp = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/GetStatusResponse"
	ActionRenew         = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Renew"
	ActionRenewResp     = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/RenewResponse"
	ActionRelease       = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release"
	ActionReleaseResp   = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/ReleaseResponse"

	ActionPut        = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
	ActionPutResp    = "http://schemas.xmlsoap.org/ws/2004/09/transfer/PutResponse"
	ActionDelete     = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	ActionDeleteResp = "http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse"
	ActionCreate     = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	ActionCreateResp = "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse"
	ActionGet        = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
	ActionGetResp    = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"

	ActionChangeOptionalFeature         = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/ChangeOptionalFeature"
	ActionChangeOptionalFeatureResponse = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/ChangeOptionalFeatureResponse"
	ActionGetADDomain                   = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADDomain"
	ActionGetADDomainResponse           = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADDomainResponse"
	ActionGetADDomainController         = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADDomainController"
	ActionGetADDomainControllerResponse = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADDomainControllerResponse"
	ActionGetADForest                   = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADForest"
	ActionGetADForestResponse           = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADForestResponse"
	ActionGetVersion                    = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetVersion"
	ActionGetVersionResponse            = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetVersionResponse"

	ActionChangePassword                           = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/ChangePassword"
	ActionGetADGroupMember                         = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADGroupMember"
	ActionGetADGroupMemberResponse                 = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADGroupMemberResponse"
	ActionGetADPrincipalAuthorizationGroup         = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADPrincipalAuthorizationGroup"
	ActionGetADPrincipalAuthorizationGroupResponse = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADPrincipalAuthorizationGroupResponse"
	ActionGetADPrincipalGroupMembership            = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADPrincipalGroupMembership"
	ActionGetADPrincipalGroupMembershipResponse    = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/GetADPrincipalGroupMembershipResponse"
	ActionSetPassword                              = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/SetPassword"
	ActionTranslateName                            = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/AccountManagement/TranslateName"
)

const (
	ResourceInstance = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/Instance"
	AddressAnonymous = "http://www.w3.org/2005/08/addressing/anonymous"

	DialectXPathLevel1 = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1"
	DialectLdapQuery   = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"
)

func ScopeToString(scope int) string {
	switch scope {
	case 0:
		return "Base"
	case 1:
		return "OneLevel"
	case 2:
		return "Subtree"
	default:
		return "Subtree"
	}
}

func generateMessageID() string {
	uuidBytes := make([]byte, 16)
	_, _ = rand.Read(uuidBytes)
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(uuidBytes[0:4]),
		binary.BigEndian.Uint16(uuidBytes[4:6]),
		binary.BigEndian.Uint16(uuidBytes[6:8]),
		binary.BigEndian.Uint16(uuidBytes[8:10]),
		uuidBytes[10:16],
	)
}

func escapeXMLLocalName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return ""
	}
	return s
}

func escapeXML(s string) string {
	if s == "" {
		return ""
	}

	// Escape XML special characters and drop characters that are invalid in XML 1.0.
	// Valid ranges: https://www.w3.org/TR/xml/#charsets
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !isValidXML10Rune(r) {
			continue
		}
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isValidXML10Rune(r rune) bool {
	// XML 1.0 valid character ranges.
	// Keep Tab, LF, CR; keep the common Unicode ranges; drop the rest.
	return r == 0x9 || r == 0xA || r == 0xD ||
		(r >= 0x20 && r <= 0xD7FF) ||
		(r >= 0xE000 && r <= 0xFFFD) ||
		(r >= 0x10000 && r <= 0x10FFFF)
}

// PrettyXML attempts to pretty-print an XML document.
// If formatting fails, it returns the original input.
func PrettyXML(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return trimmed
	}

	dec := xml.NewDecoder(strings.NewReader(trimmed))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")

	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return input
		}
		if err := enc.EncodeToken(tok); err != nil {
			return input
		}
	}
	if err := enc.Flush(); err != nil {
		return input
	}
	return buf.String()
}

func decodeBinaryAttribute(attrName, base64Value string) (string, []byte, error) {
	rawBytes, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return "", nil, err
	}

	switch detectAttributeType(attrName) {
	case "sid":
		sidStr, err := convertSIDBytes(rawBytes)
		if err != nil {
			return "", rawBytes, fmt.Errorf("failed to convert SID: %w", err)
		}
		return sidStr, rawBytes, nil
	case "guid":
		guidStr, err := convertGUIDBytes(rawBytes)
		if err != nil {
			return "", rawBytes, fmt.Errorf("failed to convert GUID: %w", err)
		}
		return guidStr, rawBytes, nil
	case "int32":
		if len(rawBytes) >= 4 {
			val := int32(binary.LittleEndian.Uint32(rawBytes[0:4]))
			return fmt.Sprintf("%d", val), rawBytes, nil
		}
		return fmt.Sprintf("%x", rawBytes), rawBytes, nil
	default:
		return fmt.Sprintf("%x", rawBytes), rawBytes, nil
	}
}

func convertSIDBytes(sidBytes []byte) (string, error) {
	if len(sidBytes) < 8 {
		return "", fmt.Errorf("SID too short: %d bytes", len(sidBytes))
	}

	revision := sidBytes[0]
	subAuthorityCount := sidBytes[1]

	authority := uint64(0)
	for i := 0; i < 6; i++ {
		authority = (authority << 8) | uint64(sidBytes[2+i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	offset := 8
	for i := 0; i < int(subAuthorityCount); i++ {
		if offset+4 > len(sidBytes) {
			return "", fmt.Errorf("SID truncated at SubAuthority %d", i)
		}
		subAuth := binary.LittleEndian.Uint32(sidBytes[offset : offset+4])
		sid += fmt.Sprintf("-%d", subAuth)
		offset += 4
	}

	return sid, nil
}

func convertGUIDBytes(guidBytes []byte) (string, error) {
	if len(guidBytes) != 16 {
		return "", fmt.Errorf("GUID must be 16 bytes, got %d", len(guidBytes))
	}

	data1 := binary.LittleEndian.Uint32(guidBytes[0:4])
	data2 := binary.LittleEndian.Uint16(guidBytes[4:6])
	data3 := binary.LittleEndian.Uint16(guidBytes[6:8])
	data4 := guidBytes[8:16]

	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		data1, data2, data3,
		data4[0], data4[1],
		data4[2], data4[3], data4[4], data4[5], data4[6], data4[7],
	), nil
}

func detectAttributeType(attrName string) string {
	lower := strings.ToLower(attrName)

	switch {
	case lower == "objectsid", lower == "sidhistory":
		return "sid"
	case lower == "objectguid", lower == "schemaidguid", lower == "attributesecurityguid",
		lower == "ms-ds-consistencyguid":
		return "guid"
	case lower == "useraccountcontrol", lower == "systemflags", lower == "searchflags",
		lower == "grouptype":
		return "int32"
	case lower == "usercertificate", lower == "thumbnailphoto", lower == "jpegphoto":
		return "binary"
	default:
		return "unknown"
	}
}

func buildIMDAAttributeTypeAndValue(attrType, xsiType, value string) string {
	return fmt.Sprintf(
		"    <da:AttributeTypeAndValue>\n      <da:AttributeType>%s</da:AttributeType>\n      <da:AttributeValue><ad:value xsi:type=\"%s\">%s</ad:value></da:AttributeValue>\n    </da:AttributeTypeAndValue>\n",
		escapeXML(strings.TrimSpace(attrType)),
		escapeXML(strings.TrimSpace(xsiType)),
		escapeXML(value),
	)
}

func encodeUTF16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	buf := make([]byte, len(encoded)*2)
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}
	return buf
}
