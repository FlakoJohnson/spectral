package enum

// single.go — look up individual objects by name or DN.
// Useful when you already know your target and want to avoid a full sweep.

import (
	"fmt"
	"log"
	"strings"

	"spectral/internal/adws"
)

// SingleResult wraps a looked-up object with its resolved group memberships.
type SingleResult struct {
	Object      adws.ADObject   `json:"object"`
	MemberOf    []adws.ADObject `json:"member_of,omitempty"`
	GroupMember []adws.ADObject `json:"group_members,omitempty"` // populated for groups
}

// singleUserAttrs pulls everything useful about a user.
var singleUserAttrs = append(userAttrs,
	"msDS-AllowedToDelegateTo",
	"msDS-KeyCredentialLink",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
)

// singleComputerAttrs pulls everything useful about a computer.
// Note: LAPS attributes (ms-Mcs-AdmPwd, msLAPS-Password) are omitted here
// because ADWS rejects the entire query if the attribute doesn't exist in
// the domain's schema. Use -m laps for LAPS enumeration instead.
var singleComputerAttrs = append(computerAttrs,
	"msDS-AllowedToDelegateTo",
	"msDS-KeyCredentialLink",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
)

// LookupUser fetches a single user by sAMAccountName and resolves their groups.
func (e *Enumerator) LookupUser(sam string) (*SingleResult, error) {
	if e.verbose {
		log.Printf("%s [*] Lookup user: %s", ts(), sam)
	}

	filter := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))",
		escapeLDAPKeepWild(sam))

	objs, err := e.client.Query(e.baseDN, filter, singleUserAttrs, adws.ScopeSubtree)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("user not found: %s", sam)
	}

	result := &SingleResult{Object: objs[0]}

	// Resolve each memberOf DN to a full group object.
	result.MemberOf, err = e.resolveGroupDNs(attrSlice(objs[0], "memberOf"))
	return result, err
}

// LookupComputer fetches a single computer by sAMAccountName (with or without $).
func (e *Enumerator) LookupComputer(name string) (*SingleResult, error) {
	if e.verbose {
		log.Printf("%s [*] Lookup computer: %s", ts(), name)
	}

	// Normalise: strip trailing $ if provided, LDAP sam for computers ends in $.
	sam := strings.TrimSuffix(name, "$") + "$"
	filter := fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s))", escapeLDAPKeepWild(sam))

	objs, err := e.client.Query(e.baseDN, filter, singleComputerAttrs, adws.ScopeSubtree)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("computer not found: %s", name)
	}

	result := &SingleResult{Object: objs[0]}
	result.MemberOf, err = e.resolveGroupDNs(attrSlice(objs[0], "memberOf"))
	return result, err
}

// LookupGroup fetches a single group by name and resolves its direct members.
func (e *Enumerator) LookupGroup(name string) (*SingleResult, error) {
	results, err := e.LookupGroups(name)
	if err != nil {
		return nil, err
	}
	return results[0], nil
}

// LookupGroups fetches groups matching name (supports * wildcards) and resolves members.
func (e *Enumerator) LookupGroups(name string) ([]*SingleResult, error) {
	if e.verbose {
		log.Printf("%s [*] Lookup group: %s", ts(), name)
	}

	filter := fmt.Sprintf("(&(objectCategory=group)(sAMAccountName=%s))", escapeLDAPKeepWild(name))

	objs, err := e.client.Query(e.baseDN, filter, groupAttrs, adws.ScopeSubtree)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("group not found: %s", name)
	}

	var results []*SingleResult
	for _, obj := range objs {
		result := &SingleResult{Object: obj}

		// Resolve members — single batch query with combined attrs (1 ADWS request).
		memberDNs := attrSlice(obj, "member")
		if e.verbose {
			sam := AttrStr(obj, "sAMAccountName")
			log.Printf("%s [*]   %s: %d members", ts(), sam, len(memberDNs))
		}

		if len(memberDNs) > 0 {
			var filterParts []string
			for _, dn := range memberDNs {
				filterParts = append(filterParts, fmt.Sprintf("(distinguishedName=%s)", escapeLDAP(dn)))
			}
			batchFilter := fmt.Sprintf("(|%s)", strings.Join(filterParts, ""))

			memberObjs, err := e.client.Query(e.domainDN, batchFilter, memberLookupAttrs, adws.ScopeSubtree)
			if err == nil {
				result.GroupMember = memberObjs
			}
		}

		results = append(results, result)
		e.pace.BetweenRequests()
	}

	return results, nil
}

// LookupOU enumerates all direct children of an OU distinguished name.
func (e *Enumerator) LookupOU(ouDN string) ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Lookup OU: %s", ts(), ouDN)
	}

	// Pull all object types one level deep within the OU.
	filter := "(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))"
	attrs := []string{
		"sAMAccountName", "distinguishedName", "objectClass",
		"objectSid", "userAccountControl", "dNSHostName",
	}

	return e.client.Query(ouDN, filter, attrs, adws.ScopeOneLevel)
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

// resolveGroupDNs takes a slice of group DNs and returns lightweight objects.
func (e *Enumerator) resolveGroupDNs(dns []string) ([]adws.ADObject, error) {
	if len(dns) == 0 {
		return nil, nil
	}

	out := make([]adws.ADObject, 0, len(dns))
	attrs := []string{"sAMAccountName", "distinguishedName", "objectSid", "adminCount"}

	for _, dn := range dns {
		objs, err := e.client.Query(
			e.baseDN,
			fmt.Sprintf("(distinguishedName=%s)", escapeLDAP(dn)),
			attrs,
			adws.ScopeSubtree,
		)
		if err != nil || len(objs) == 0 {
			continue
		}
		out = append(out, objs[0])
		e.pace.BetweenRequests()
	}

	return out, nil
}

// AttrSliceStr returns all values of an attribute as a string slice.
// Attributes is map[string][]ADWSValue — key is the attribute name.
func AttrSliceStr(obj adws.ADObject, name string) []string {
	vals, ok := obj.Attributes[name]
	if !ok || len(vals) == 0 {
		return []string{}
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = v.Value
	}
	return strs
}

// attrSlice is the package-private alias.
func attrSlice(obj adws.ADObject, name string) []string { return AttrSliceStr(obj, name) }

// escapeLDAP escapes special characters in an LDAP filter value.
// Prevents filter injection when user-supplied names are used.
// escapeLDAPKeepWild escapes LDAP special chars but preserves * for wildcard searches.
func escapeLDAPKeepWild(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\5c`,
		`(`, `\28`,
		`)`, `\29`,
		"\x00", `\00`,
	)
	return replacer.Replace(s)
}

func escapeLDAP(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\5c`,
		`*`, `\2a`,
		`(`, `\28`,
		`)`, `\29`,
		"\x00", `\00`,
	)
	return replacer.Replace(s)
}
