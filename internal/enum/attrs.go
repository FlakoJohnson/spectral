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
	"primaryGroupID",
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
	"primaryGroupID",
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

// memberLookupAttrs — superset of user + computer + group attrs for batch member resolution.
// ADWS only returns attributes that exist on each object, so requesting extra is safe.
// Single query instead of per-member lookups = stealth.
var memberLookupAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectSid",
	"objectGUID",
	"objectClass",
	"userPrincipalName",
	"memberOf",
	"member",
	"primaryGroupID",
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
	"dNSHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"groupType",
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
