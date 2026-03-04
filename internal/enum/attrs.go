package enum

// Attribute sets per object type.
// Kept minimal — only what BloodHound/analysis actually needs.
// Requesting fewer attributes reduces query volume and log noise.

var userAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"userPrincipalName",
	"objectSid",
	"objectGUID",
	"memberOf",
	"adminCount",
	"userAccountControl",
	"servicePrincipalName",
	"pwdLastSet",
	"lastLogon",
	"lastLogonTimestamp",
	"description",
	"mail",
	"displayName",
	"whenCreated",
	"nTSecurityDescriptor",
}

var computerAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"dNSHostName",
	"objectSid",
	"objectGUID",
	"memberOf",
	"userAccountControl",
	"operatingSystem",
	"operatingSystemVersion",
	"lastLogon",
	"lastLogonTimestamp",
	"servicePrincipalName",
	"whenCreated",
	"nTSecurityDescriptor",
}

var groupAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectSid",
	"objectGUID",
	"member",
	"memberOf",
	"groupType",
	"adminCount",
	"description",
	"whenCreated",
	"nTSecurityDescriptor",
}

var gpoAttrs = []string{
	"displayName",
	"distinguishedName",
	"objectGUID",
	"gPCFileSysPath",
	"versionNumber",
	"flags",
	"whenCreated",
	"nTSecurityDescriptor",
}

var trustAttrs = []string{
	"name",
	"distinguishedName",
	"trustDirection",
	"trustType",
	"trustAttributes",
	"securityIdentifier",
	"flatName",
	"whenCreated",
}

var ouAttrs = []string{
	"name",
	"distinguishedName",
	"objectGUID",
	"gPLink",
	"gPOptions",
	"description",
	"whenCreated",
	"nTSecurityDescriptor",
}
