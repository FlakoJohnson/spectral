package soap

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func BuildGetRequest(dn string, attrs []string, ldapPort int) string {
	msgID := generateMessageID()
	attrTypeXML := ""
	for _, attr := range attrs {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		attrTypeXML += fmt.Sprintf("    <da:AttributeType>addata:%s</da:AttributeType>\n", escapeXML(attr))
	}
	if attrTypeXML == "" {
		return BuildGetRequest(dn, []string{"distinguishedName"}, ldapPort)
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<ad:objectReferenceProperty>%s</ad:objectReferenceProperty>
		<da:IdentityManagementOperation s:mustUnderstand="1" />
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body>
		<da:BaseObjectSearchRequest Dialect="%s">
%s		</da:BaseObjectSearchRequest>
	</s:Body>
</s:Envelope>`, ActionGet, ldapPort, escapeXML(dn), msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrTypeXML)
}

func BuildDeleteRequest(dn string, ldapPort int) string {
	msgID := generateMessageID()

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<ad:objectReferenceProperty>%s</ad:objectReferenceProperty>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body/>
</s:Envelope>`, ActionDelete, ldapPort, escapeXML(dn), msgID, AddressAnonymous, ResourceInstance)
}

func BuildPutRequest(dn, instanceXML string, ldapPort int) string {
	msgID := generateMessageID()
	instanceXML = strings.TrimSpace(instanceXML)

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<ad:objectReferenceProperty>%s</ad:objectReferenceProperty>
		<da:IdentityManagementOperation s:mustUnderstand="1" />
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body>
%s
	</s:Body>
</s:Envelope>`, ActionPut, ldapPort, escapeXML(dn), msgID, AddressAnonymous, ResourceInstance, instanceXML)
}

func BuildCreateRequest(instanceXML string, ldapPort int) string {
	msgID := generateMessageID()
	instanceXML = strings.TrimSpace(instanceXML)

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<da:IdentityManagementOperation s:mustUnderstand="1" />
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body>
%s
	</s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, instanceXML)
}

// BuildModifyRequest builds an IMDA ModifyRequest XML payload suitable to be used as the body for WS-Transfer Put.
//
// operation must be one of: add, replace, delete.
// attr may be either a full type (e.g. "addata:description") or a local attribute name (e.g. "description").
// If attr has no prefix, it is treated as an AD data attribute and is converted to "addata:<name>".
//
// xsiType controls the ad:value xsi:type used (defaults to xsd:string).
func BuildModifyRequest(operation, attr string, values []string, xsiType string) (string, error) {
	op := strings.ToLower(strings.TrimSpace(operation))
	attr = strings.TrimSpace(attr)
	if attr == "" {
		return "", fmt.Errorf("attr is required")
	}
	if op != "add" && op != "replace" && op != "delete" {
		return "", fmt.Errorf("invalid operation %q", operation)
	}

	attrType := attr
	if !strings.Contains(attrType, ":") {
		localName := escapeXMLLocalName(attrType)
		if localName == "" {
			return "", fmt.Errorf("invalid attribute name %q", attr)
		}
		attrType = "addata:" + localName
	}

	xsiType = strings.TrimSpace(xsiType)
	if xsiType == "" {
		xsiType = "xsd:string"
	}

	valuesXML := ""
	for _, v := range values {
		valuesXML += fmt.Sprintf("        <ad:value xsi:type=\"%s\">%s</ad:value>\n", escapeXML(xsiType), escapeXML(v))
	}

	attrValueXML := ""
	if op != "delete" {
		if strings.TrimSpace(valuesXML) == "" {
			return "", fmt.Errorf("values is required for %s", op)
		}
		attrValueXML = fmt.Sprintf("      <da:AttributeValue>\n%s      </da:AttributeValue>\n", valuesXML)
	}

	// These controls have been observed in other implementations and have been kept for compatibility.
	controlsXML := "" +
		"  <ad:controls>\n" +
		"    <ad:control type=\"1.2.840.113556.1.4.1413\" criticality=\"true\" />\n" +
		"    <ad:control type=\"1.2.840.113556.1.4.801\" criticality=\"true\">\n" +
		"      <ad:controlValue xsi:type=\"xsd:base64Binary\">MIQAAAADAgEH</ad:controlValue>\n" +
		"    </ad:control>\n" +
		"  </ad:controls>\n"

	return fmt.Sprintf(
		"<da:ModifyRequest Dialect=\"%s\" xmlns:da=\"http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess\" xmlns:addata=\"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data\" xmlns:ad=\"http://schemas.microsoft.com/2008/1/ActiveDirectory\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n"+
			"  <da:Change Operation=\"%s\">\n"+
			"    <da:AttributeType>%s</da:AttributeType>\n"+
			"%s"+
			"  </da:Change>\n"+
			"%s"+
			"</da:ModifyRequest>",
		DialectXPathLevel1,
		escapeXML(op),
		escapeXML(attrType),
		attrValueXML,
		controlsXML,
	), nil
}

func BuildCreateComputerRequest(parentDN, computerName string, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	computerName = strings.TrimSpace(computerName)
	if computerName == "" {
		return "", fmt.Errorf("computerName is required")
	}

	cn := strings.TrimSuffix(computerName, "$")
	samAccountName := cn + "$"

	msgID := generateMessageID()

	attrBlocks := strings.Join([]string{
		buildIMDAAttributeTypeAndValue("addata:objectClass", "xsd:string", "computer"),
		buildIMDAAttributeTypeAndValue("addata:sAMAccountName", "xsd:string", samAccountName),
		buildIMDAAttributeTypeAndValue("addata:userAccountControl", "xsd:int", "4096"),
		buildIMDAAttributeTypeAndValue("ad:relativeDistinguishedName", "xsd:string", "CN="+cn),
		buildIMDAAttributeTypeAndValue("ad:container-hierarchy-parent", "xsd:string", parentDN),
	}, "")

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}

// BuildAddComputerRequest builds a WS-Transfer Create (IMDA AddRequest) that creates
// a computer account under parentDN, mirroring SharpADWS' AddComputer method.
//
// Required inputs:
//   - parentDN: container DN (SharpADWS uses CN=Computers,<defaultNamingContext>)
//   - computerName: may include or omit trailing '$'
//   - domainName: used to build dNSHostName and SPN
//   - computerPass: will be encoded as unicodePwd (UTF-16LE with quotes)
func BuildAddComputerRequest(parentDN, computerName, domainName, computerPass string, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	computerName = strings.TrimSpace(computerName)
	if computerName == "" {
		return "", fmt.Errorf("computerName is required")
	}
	domainName = strings.TrimSpace(domainName)
	if domainName == "" {
		return "", fmt.Errorf("domainName is required")
	}
	if computerPass == "" {
		return "", fmt.Errorf("computerPass is required")
	}

	cn := strings.TrimSuffix(computerName, "$")
	samAccountName := cn + "$"
	dnsHostName := fmt.Sprintf("%s.%s", cn, domainName)

	// SharpADWS sets a single SPN string here.
	servicePrincipalName := fmt.Sprintf("HOST/%s", cn)

	unicodePwdB64 := base64.StdEncoding.EncodeToString(encodeUTF16LE("\"" + computerPass + "\""))

	msgID := generateMessageID()

	attrBlocks := strings.Join([]string{
		buildIMDAAttributeTypeAndValue("addata:objectClass", "xsd:string", "computer"),
		buildIMDAAttributeTypeAndValue("addata:dNSHostName", "xsd:string", dnsHostName),
		buildIMDAAttributeTypeAndValue("addata:userAccountControl", "xsd:string", "4096"),
		buildIMDAAttributeTypeAndValue("addata:servicePrincipalName", "xsd:string", servicePrincipalName),
		buildIMDAAttributeTypeAndValue("addata:sAMAccountName", "xsd:string", samAccountName),
		buildIMDAAttributeTypeAndValue("addata:unicodePwd", "xsd:base64Binary", unicodePwdB64),
		buildIMDAAttributeTypeAndValue("ad:relativeDistinguishedName", "xsd:string", "CN="+cn),
		buildIMDAAttributeTypeAndValue("ad:container-hierarchy-parent", "xsd:string", parentDN),
	}, "")

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}

// BuildAddUserRequest builds a WS-Transfer Create (IMDA AddRequest) that creates
// a user account under parentDN.
//
// Notes:
//   - If userPass is empty, the user is created disabled (userAccountControl=514).
//   - If userPass is set, unicodePwd is set; if enabled is true, userAccountControl=512
//     else 514.
func BuildAddUserRequest(parentDN, userName, domainName, userPass string, enabled bool, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return "", fmt.Errorf("userName is required")
	}
	domainName = strings.TrimSpace(domainName)
	if domainName == "" {
		return "", fmt.Errorf("domainName is required")
	}
	cn := userName
	samAccountName := userName
	upn := fmt.Sprintf("%s@%s", userName, domainName)

	userAccountControl := "514" // NORMAL_ACCOUNT | ACCOUNTDISABLE
	if userPass != "" && enabled {
		userAccountControl = "512" // NORMAL_ACCOUNT
	}

	msgID := generateMessageID()

	blocks := []string{
		buildIMDAAttributeTypeAndValue("addata:objectClass", "xsd:string", "user"),
		buildIMDAAttributeTypeAndValue("addata:cn", "xsd:string", cn),
		buildIMDAAttributeTypeAndValue("addata:sAMAccountName", "xsd:string", samAccountName),
		buildIMDAAttributeTypeAndValue("addata:userPrincipalName", "xsd:string", upn),
		buildIMDAAttributeTypeAndValue("addata:sn", "xsd:string", cn),
		buildIMDAAttributeTypeAndValue("addata:userAccountControl", "xsd:string", userAccountControl),
	}
	if userPass != "" {
		unicodePwdB64 := base64.StdEncoding.EncodeToString(encodeUTF16LE("\"" + userPass + "\""))
		blocks = append(blocks, buildIMDAAttributeTypeAndValue("addata:unicodePwd", "xsd:base64Binary", unicodePwdB64))
	}
	blocks = append(blocks,
		buildIMDAAttributeTypeAndValue("ad:relativeDistinguishedName", "xsd:string", "CN="+cn),
		buildIMDAAttributeTypeAndValue("ad:container-hierarchy-parent", "xsd:string", parentDN),
	)

	attrBlocks := strings.Join(blocks, "")

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}

// BuildAddGroupRequest builds a WS-Transfer Create (IMDA AddRequest) that creates
// a group under parentDN.
//
// groupType defaults to global security group if empty.
func BuildAddGroupRequest(parentDN, groupName string, groupType string, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return "", fmt.Errorf("groupName is required")
	}
	groupType = strings.TrimSpace(groupType)
	if groupType == "" {
		// Global security group: 0x80000002
		groupType = "-2147483646"
	}

	cn := groupName
	samAccountName := groupName

	msgID := generateMessageID()
	attrBlocks := strings.Join([]string{
		buildIMDAAttributeTypeAndValue("addata:objectClass", "xsd:string", "group"),
		buildIMDAAttributeTypeAndValue("addata:cn", "xsd:string", cn),
		buildIMDAAttributeTypeAndValue("addata:sAMAccountName", "xsd:string", samAccountName),
		buildIMDAAttributeTypeAndValue("addata:groupType", "xsd:string", groupType),
		buildIMDAAttributeTypeAndValue("ad:relativeDistinguishedName", "xsd:string", "CN="+cn),
		buildIMDAAttributeTypeAndValue("ad:container-hierarchy-parent", "xsd:string", parentDN),
	}, "")

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}

func BuildAddOURequest(parentDN, ouName string, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	ouName = strings.TrimSpace(ouName)
	if ouName == "" {
		return "", fmt.Errorf("ouName is required")
	}

	msgID := generateMessageID()
	attrBlocks := strings.Join([]string{
		buildIMDAAttributeTypeAndValue("addata:objectClass", "xsd:string", "organizationalUnit"),
		buildIMDAAttributeTypeAndValue("addata:ou", "xsd:string", ouName),
		buildIMDAAttributeTypeAndValue("ad:relativeDistinguishedName", "xsd:string", "OU="+ouName),
		buildIMDAAttributeTypeAndValue("ad:container-hierarchy-parent", "xsd:string", parentDN),
	}, "")

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}

func BuildAddContainerRequest(parentDN, cn string, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return "", fmt.Errorf("cn is required")
	}

	msgID := generateMessageID()
	attrBlocks := strings.Join([]string{
		buildIMDAAttributeTypeAndValue("addata:objectClass", "xsd:string", "container"),
		buildIMDAAttributeTypeAndValue("addata:cn", "xsd:string", cn),
		buildIMDAAttributeTypeAndValue("ad:relativeDistinguishedName", "xsd:string", "CN="+cn),
		buildIMDAAttributeTypeAndValue("ad:container-hierarchy-parent", "xsd:string", parentDN),
	}, "")

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}

// IMDAAttributeSpec represents a single attribute for an IMDA AddRequest.
// Values may contain 1+ entries for multi-valued attributes.
type IMDAAttributeSpec struct {
	AttrType string
	XSIType  string
	Values   []string
}

func buildIMDAAttributeTypeAndValues(attrType, xsiType string, values []string) (string, error) {
	attrType = strings.TrimSpace(attrType)
	xsiType = strings.TrimSpace(xsiType)
	if attrType == "" {
		return "", fmt.Errorf("attrType is required")
	}
	if xsiType == "" {
		return "", fmt.Errorf("xsiType is required")
	}
	if len(values) == 0 {
		return "", fmt.Errorf("values is required")
	}

	var valuesXML strings.Builder
	for _, v := range values {
		valuesXML.WriteString(fmt.Sprintf("        <ad:value xsi:type=\"%s\">%s</ad:value>\n", escapeXML(xsiType), escapeXML(v)))
	}

	return fmt.Sprintf(
		"    <da:AttributeTypeAndValue>\n"+
			"      <da:AttributeType>%s</da:AttributeType>\n"+
			"      <da:AttributeValue>\n"+
			"%s"+
			"      </da:AttributeValue>\n"+
			"    </da:AttributeTypeAndValue>\n",
		escapeXML(attrType),
		valuesXML.String(),
	), nil
}

// BuildAddCustomRequest builds a WS-Transfer Create (IMDA AddRequest) against the ResourceFactory endpoint
// with user-provided attributes.
//
// parentDN is the container DN; rdn is the relative distinguished name (e.g. "CN=Foo").
// ldapPort controls the ad:instance header (389=DC, 3268=GC).
func BuildAddCustomRequest(parentDN, rdn string, attrs []IMDAAttributeSpec, ldapPort int) (string, error) {
	parentDN = strings.TrimSpace(parentDN)
	rdn = strings.TrimSpace(rdn)
	if parentDN == "" {
		return "", fmt.Errorf("parentDN is required")
	}
	if rdn == "" {
		return "", fmt.Errorf("rdn is required")
	}
	if len(attrs) == 0 {
		return "", fmt.Errorf("attrs is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	blocks := make([]string, 0, len(attrs)+2)
	for i := 0; i < len(attrs); i++ {
		a := attrs[i]
		b, err := buildIMDAAttributeTypeAndValues(a.AttrType, a.XSIType, a.Values)
		if err != nil {
			return "", fmt.Errorf("attrs[%d]: %w", i, err)
		}
		blocks = append(blocks, b)
	}

	// Required IMDA metadata.
	rdnBlock, err := buildIMDAAttributeTypeAndValues("ad:relativeDistinguishedName", "xsd:string", []string{rdn})
	if err != nil {
		return "", err
	}
	parentBlock, err := buildIMDAAttributeTypeAndValues("ad:container-hierarchy-parent", "xsd:string", []string{parentDN})
	if err != nil {
		return "", err
	}
	blocks = append(blocks, rdnBlock, parentBlock)

	attrBlocks := strings.Join(blocks, "")
	msgID := generateMessageID()

	soapXML := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <s:Header>
	<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ad:instance>ldap:%d</ad:instance>
    <da:IdentityManagementOperation s:mustUnderstand="1" />
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
		<da:AddRequest Dialect="%s">
%s    </da:AddRequest>
  </s:Body>
</s:Envelope>`, ActionCreate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectXPathLevel1, attrBlocks)

	return soapXML, nil
}
