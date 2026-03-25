package soap

import (
	"fmt"
	"regexp"
	"strings"
)

var guidRegexp = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func BuildChangeOptionalFeatureRequest(distinguishedName string, enable bool, featureID string, ldapPort int) (string, error) {
	distinguishedName = strings.TrimSpace(distinguishedName)
	featureID = strings.TrimSpace(featureID)
	if distinguishedName == "" {
		return "", fmt.Errorf("distinguishedName is required")
	}
	if featureID == "" {
		return "", fmt.Errorf("featureID is required")
	}
	if !guidRegexp.MatchString(featureID) {
		return "", fmt.Errorf("featureID must be a GUID in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, got %q", featureID)
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	msgID := generateMessageID()
	enableXML := "false"
	if enable {
		enableXML = "true"
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <ChangeOptionalFeatureRequest xmlns="%s">
      <DistinguishedName>%s</DistinguishedName>
      <Enable>%s</Enable>
      <FeatureId>%s</FeatureId>
    </ChangeOptionalFeatureRequest>
  </s:Body>
</s:Envelope>`,
		ActionChangeOptionalFeature,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(distinguishedName),
		enableXML,
		escapeXML(featureID),
	), nil
}

func BuildGetADDomainRequest(ldapPort int) (string, error) {
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}
	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetADDomainRequest xmlns="%s" />
  </s:Body>
</s:Envelope>`,
		ActionGetADDomain,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
	), nil
}

func BuildGetADForestRequest(ldapPort int) (string, error) {
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}
	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetADForestRequest xmlns="%s" />
  </s:Body>
</s:Envelope>`,
		ActionGetADForest,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
	), nil
}

func BuildGetVersionRequest(ldapPort int) (string, error) {
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}
	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetVersionRequest xmlns="%s" />
  </s:Body>
</s:Envelope>`,
		ActionGetVersion,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
	), nil
}

func BuildGetADDomainControllerRequest(ntdsSettingsDNs []string, ldapPort int) (string, error) {
	if len(ntdsSettingsDNs) == 0 {
		return "", fmt.Errorf("at least one ntdsSettingsDN is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	var arrayXML strings.Builder
	for _, dn := range ntdsSettingsDNs {
		dn = strings.TrimSpace(dn)
		if dn == "" {
			return "", fmt.Errorf("ntdsSettingsDNs contains an empty string")
		}
		arrayXML.WriteString(fmt.Sprintf("        <sera:string>%s</sera:string>\n", escapeXML(dn)))
	}

	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetADDomainControllerRequest xmlns="%s" xmlns:sera="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
      <NtdsSettingsDN>
%s      </NtdsSettingsDN>
    </GetADDomainControllerRequest>
  </s:Body>
</s:Envelope>`,
		ActionGetADDomainController,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		arrayXML.String(),
	), nil
}

func BuildGetADGroupMemberRequest(groupDN, partitionDN string, recursive bool, ldapPort int) (string, error) {
	groupDN = strings.TrimSpace(groupDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if groupDN == "" {
		return "", fmt.Errorf("groupDN is required")
	}
	if partitionDN == "" {
		return "", fmt.Errorf("partitionDN is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	msgID := generateMessageID()
	recursiveXML := "false"
	if recursive {
		recursiveXML = "true"
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetADGroupMemberRequest xmlns="%s">
      <GroupDN>%s</GroupDN>
      <PartitionDN>%s</PartitionDN>
      <Recursive>%s</Recursive>
    </GetADGroupMemberRequest>
  </s:Body>
</s:Envelope>`,
		ActionGetADGroupMember,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(groupDN),
		escapeXML(partitionDN),
		recursiveXML,
	), nil
}

func BuildGetADPrincipalAuthorizationGroupRequest(partitionDN, principalDN string, ldapPort int) (string, error) {
	partitionDN = strings.TrimSpace(partitionDN)
	principalDN = strings.TrimSpace(principalDN)
	if partitionDN == "" {
		return "", fmt.Errorf("partitionDN is required")
	}
	if principalDN == "" {
		return "", fmt.Errorf("principalDN is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	msgID := generateMessageID()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetADPrincipalAuthorizationGroupRequest xmlns="%s">
      <PartitionDN>%s</PartitionDN>
      <PrincipalDN>%s</PrincipalDN>
    </GetADPrincipalAuthorizationGroupRequest>
  </s:Body>
</s:Envelope>`,
		ActionGetADPrincipalAuthorizationGroup,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(partitionDN),
		escapeXML(principalDN),
	), nil
}

func BuildGetADPrincipalGroupMembershipRequest(partitionDN, principalDN, resourceContextPartition, resourceContextServer string, ldapPort int) (string, error) {
	partitionDN = strings.TrimSpace(partitionDN)
	principalDN = strings.TrimSpace(principalDN)
	resourceContextPartition = strings.TrimSpace(resourceContextPartition)
	resourceContextServer = strings.TrimSpace(resourceContextServer)
	if partitionDN == "" {
		return "", fmt.Errorf("partitionDN is required")
	}
	if principalDN == "" {
		return "", fmt.Errorf("principalDN is required")
	}
	if (resourceContextPartition == "") != (resourceContextServer == "") {
		return "", fmt.Errorf("resourceContextPartition and resourceContextServer must be specified together")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	msgID := generateMessageID()

	resourceContextXML := ""
	if resourceContextPartition != "" {
		resourceContextXML = fmt.Sprintf("      <ResourceContextPartition>%s</ResourceContextPartition>\n      <ResourceContextServer>%s</ResourceContextServer>\n", escapeXML(resourceContextPartition), escapeXML(resourceContextServer))
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <GetADPrincipalGroupMembershipRequest xmlns="%s">
      <PartitionDN>%s</PartitionDN>
      <PrincipalDN>%s</PrincipalDN>
%s    </GetADPrincipalGroupMembershipRequest>
  </s:Body>
</s:Envelope>`,
		ActionGetADPrincipalGroupMembership,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(partitionDN),
		escapeXML(principalDN),
		resourceContextXML,
	), nil
}

func BuildChangePasswordRequest(accountDN, partitionDN, oldPassword, newPassword string, ldapPort int) (string, error) {
	accountDN = strings.TrimSpace(accountDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if accountDN == "" {
		return "", fmt.Errorf("accountDN is required")
	}
	if partitionDN == "" {
		return "", fmt.Errorf("partitionDN is required")
	}
	if oldPassword == "" {
		return "", fmt.Errorf("oldPassword is required")
	}
	if newPassword == "" {
		return "", fmt.Errorf("newPassword is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	msgID := generateMessageID()

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <ChangePasswordRequest xmlns="%s">
      <AccountDN>%s</AccountDN>
      <NewPassword>%s</NewPassword>
      <OldPassword>%s</OldPassword>
      <PartitionDN>%s</PartitionDN>
    </ChangePasswordRequest>
  </s:Body>
</s:Envelope>`,
		ActionChangePassword,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(accountDN),
		escapeXML(newPassword),
		escapeXML(oldPassword),
		escapeXML(partitionDN),
	), nil
}

func BuildSetPasswordRequest(accountDN, partitionDN, newPassword string, ldapPort int) (string, error) {
	accountDN = strings.TrimSpace(accountDN)
	partitionDN = strings.TrimSpace(partitionDN)
	if accountDN == "" {
		return "", fmt.Errorf("accountDN is required")
	}
	if partitionDN == "" {
		return "", fmt.Errorf("partitionDN is required")
	}
	if newPassword == "" {
		return "", fmt.Errorf("newPassword is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	msgID := generateMessageID()

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <SetPasswordRequest xmlns="%s">
      <AccountDN>%s</AccountDN>
      <NewPassword>%s</NewPassword>
      <PartitionDN>%s</PartitionDN>
    </SetPasswordRequest>
  </s:Body>
</s:Envelope>`,
		ActionSetPassword,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(accountDN),
		escapeXML(newPassword),
		escapeXML(partitionDN),
	), nil
}

func BuildTranslateNameRequest(formatOffered, formatDesired string, names []string, ldapPort int) (string, error) {
	formatOffered = strings.TrimSpace(formatOffered)
	formatDesired = strings.TrimSpace(formatDesired)
	if formatOffered == "" {
		return "", fmt.Errorf("formatOffered is required")
	}
	if formatDesired == "" {
		return "", fmt.Errorf("formatDesired is required")
	}
	if !isValidTranslateNameFormat(formatOffered) {
		return "", fmt.Errorf("invalid formatOffered: %q (expected DistinguishedName or CanonicalName)", formatOffered)
	}
	if !isValidTranslateNameFormat(formatDesired) {
		return "", fmt.Errorf("invalid formatDesired: %q (expected DistinguishedName or CanonicalName)", formatDesired)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("at least one name is required")
	}
	if ldapPort <= 0 || ldapPort > 65535 {
		return "", fmt.Errorf("ldapPort out of range: %d", ldapPort)
	}

	// Per MS-ADCAP 3.3.4.6.8.1, a null string element causes a Sender fault.
	var namesXML strings.Builder
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			return "", fmt.Errorf("names contains an empty string")
		}
		namesXML.WriteString(fmt.Sprintf("        <sera:string>%s</sera:string>\n", escapeXML(n)))
	}

	msgID := generateMessageID()

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">%s</wsa:Action>
    <ca:Server xmlns:ca="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions" xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions">ldap:%d</ca:Server>
    <wsa:MessageID>%s</wsa:MessageID>
    <wsa:ReplyTo>
		<wsa:Address>%s</wsa:Address>
    </wsa:ReplyTo>
	<wsa:To s:mustUnderstand="1">%s</wsa:To>
  </s:Header>
  <s:Body>
    <TranslateNameRequest xmlns="%s" xmlns:sera="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
      <FormatDesired>%s</FormatDesired>
      <FormatOffered>%s</FormatOffered>
      <Names>
%s      </Names>
    </TranslateNameRequest>
  </s:Body>
</s:Envelope>`,
		ActionTranslateName,
		ldapPort,
		msgID,
		AddressAnonymous,
		ResourceInstance,
		NsCustomActions,
		escapeXML(formatDesired),
		escapeXML(formatOffered),
		namesXML.String(),
	), nil
}

func isValidTranslateNameFormat(s string) bool {
	switch strings.TrimSpace(s) {
	case "DistinguishedName", "CanonicalName":
		return true
	default:
		return false
	}
}
