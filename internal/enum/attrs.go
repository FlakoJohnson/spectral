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
	"whenChanged",
	"nTSecurityDescriptor",
}

// Enhanced GPO attributes for comprehensive analysis - requested in batches for stealth
var gpoEnhancedAttrs = []string{
	"displayName",
	"distinguishedName",
	"objectGUID",
	"gPCFileSysPath",
	"versionNumber",
	"flags",
	"whenCreated",
	"whenChanged",
	"objectVersion",
	"gPCMachineExtensionNames", // CSE GUIDs for machine policies
	"gPCUserExtensionNames",    // CSE GUIDs for user policies
	"gPCWQLFilter",             // WMI filter DN reference
	"gPCFunctionalityVersion",  // GPO functional version
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

// WMI filter attributes for GPO analysis - queried separately to avoid suspicious patterns
var wmiFilterAttrs = []string{
	"msWMI-Name",
	"msWMI-Parm1",          // WQL query string
	"msWMI-Author",
	"msWMI-ChangeDate",
	"msWMI-CreationDate",
	"distinguishedName",
	"objectGUID",
	"nTSecurityDescriptor",
}

// Site object attributes for site-level GPO links - often missed by scanners
var siteAttrs = []string{
	"name",
	"distinguishedName",
	"objectGUID",
	"gPLink",            // Site-linked GPOs
	"gPOptions",
	"whenCreated",
	"description",
	"nTSecurityDescriptor",
}
