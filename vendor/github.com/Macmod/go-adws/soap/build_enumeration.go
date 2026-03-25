package soap

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func BuildEnumerateRequest(baseDN, filter string, attrs []string, scope int, ldapPort int) string {
	msgID := generateMessageID()
	scopeStr := ScopeToString(scope)

	selectionXML := buildSelectionXML(attrs)

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:adlq="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery">
		<wsen:Enumerate>
			<wsen:Filter Dialect="%s">
				<adlq:LdapQuery>
					<adlq:Filter>%s</adlq:Filter>
					<adlq:BaseObject>%s</adlq:BaseObject>
					<adlq:Scope>%s</adlq:Scope>
				</adlq:LdapQuery>
			</wsen:Filter>

%s
		</wsen:Enumerate>
	</s:Body>
</s:Envelope>`, ActionEnumerate, ldapPort, msgID, AddressAnonymous, ResourceInstance, DialectLdapQuery, escapeXML(filter), escapeXML(baseDN), scopeStr, selectionXML)
}

func buildSelectionXML(attrs []string) string {
	// MS-WSDS: ad:Selection is optional. If present, it MUST contain at least one SelectionProperty.
	// For convenience, we treat "*" as the selection property "ad:all" (all default attributes).
	// Note: MS-WSDS does not define LDAP-style wildcards for operational attributes ("+").
	selectionProps := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		if attr == "*" {
			selectionProps = append(selectionProps, "ad:all")
			continue
		}
		selectionProps = append(selectionProps, "addata:"+attr)
	}

	var attrsXML strings.Builder
	for _, prop := range selectionProps {
		attrsXML.WriteString(fmt.Sprintf("            <ad:SelectionProperty>%s</ad:SelectionProperty>\n", escapeXML(prop)))
	}

	return fmt.Sprintf("            <ad:Selection Dialect=\"%s\">\n%s            </ad:Selection>\n", DialectXPathLevel1, attrsXML.String())
}

func BuildPullRequest(enumerationContext string, maxElements int, ldapPort int, sdFlags int) string {
	msgID := generateMessageID()

	controlsXML := ""
	if sdFlags > 0 {
		// BER-encode SEQUENCE { INTEGER sdFlags } per LDAP_SERVER_SD_FLAGS_OID (1.2.840.113556.1.4.801).
		berData := []byte{0x30, 0x84, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, byte(sdFlags)}
		controlsXML = fmt.Sprintf("            <ad:controls>\n                <ad:control type=\"1.2.840.113556.1.4.801\" criticality=\"true\">\n                    <ad:controlValue xsi:type=\"xsd:base64Binary\">%s</ad:controlValue>\n                </ad:control>\n            </ad:controls>\n", base64.StdEncoding.EncodeToString(berData))
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
		<wsen:Pull>
			<wsen:EnumerationContext>%s</wsen:EnumerationContext>
			<wsen:MaxElements>%d</wsen:MaxElements>
%s		</wsen:Pull>
	</s:Body>
</s:Envelope>`, ActionPull, msgID, AddressAnonymous, ResourceInstance, escapeXML(enumerationContext), maxElements, controlsXML)
}

func BuildGetStatusRequest(enumerationContext string, ldapPort int) string {
	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
		<wsen:GetStatus>
			<wsen:EnumerationContext>%s</wsen:EnumerationContext>
		</wsen:GetStatus>
	</s:Body>
</s:Envelope>`, ActionGetStatus, ldapPort, msgID, AddressAnonymous, ResourceInstance, escapeXML(enumerationContext))
}

func BuildRenewRequest(enumerationContext, expires string, ldapPort int) string {
	msgID := generateMessageID()
	expiresXML := ""
	if strings.TrimSpace(expires) != "" {
		expiresXML = fmt.Sprintf("      <wsen:Expires>%s</wsen:Expires>\n", escapeXML(expires))
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
		<wsen:Renew>
			<wsen:EnumerationContext>%s</wsen:EnumerationContext>
%s    </wsen:Renew>
	</s:Body>
</s:Envelope>`, ActionRenew, ldapPort, msgID, AddressAnonymous, ResourceInstance, escapeXML(enumerationContext), expiresXML)
}

func BuildReleaseRequest(enumerationContext string, ldapPort int) string {
	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data" xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
	<s:Header>
		<wsa:Action s:mustUnderstand="1">%s</wsa:Action>
		<ad:instance>ldap:%d</ad:instance>
		<wsa:MessageID>%s</wsa:MessageID>
		<wsa:ReplyTo>
			<wsa:Address>%s</wsa:Address>
		</wsa:ReplyTo>
		<wsa:To s:mustUnderstand="1">%s</wsa:To>
	</s:Header>
	<s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
		<wsen:Release>
			<wsen:EnumerationContext>%s</wsen:EnumerationContext>
		</wsen:Release>
	</s:Body>
</s:Envelope>`, ActionRelease, ldapPort, msgID, AddressAnonymous, ResourceInstance, escapeXML(enumerationContext))
}
