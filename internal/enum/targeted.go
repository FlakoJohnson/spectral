package enum

// Package enum — targeted.go
// Surgical queries for high-value attack-path targets.
// Each query uses the narrowest possible filter to look like legitimate
// admin tooling (RSAT / PowerShell AD module patterns).

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"

	"spectral/internal/adws"
)

// UAC bitmask constants used in LDAP extensible-match filters.
// Reference: MS-ADTS section 2.2.16.
const (
	uacDisabled         = 0x00000002  // ACCOUNTDISABLE
	uacDontExpirePass   = 0x00010000  // DONT_EXPIRE_PASSWORD
	uacTrustedForDeleg  = 0x00080000  // TRUSTED_FOR_DELEGATION (unconstrained)
	uacDontReqPreauth   = 0x00400000  // DONT_REQ_PREAUTH (AS-REP roastable)
	uacDC               = 516         // primaryGroupID for Domain Controllers
	uacRODC             = 521         // primaryGroupID for Read-Only DCs
)

// uacFilter builds an LDAP extensible-match filter for a UAC bit.
func uacFilter(bit int) string {
	return fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", bit)
}

// notDisabled returns a filter fragment excluding disabled accounts.
func notDisabled() string { return fmt.Sprintf("(!%s)", uacFilter(uacDisabled)) }

// -------------------------------------------------------------------------
// Kerberoastable
// -------------------------------------------------------------------------

// Kerberoastable returns enabled user accounts that have at least one SPN
// (excluding krbtgt and machine accounts ending in $).
//
// OPSEC: Uses the same filter and attribute set as a normal user sweep
// ((&(objectCategory=person)(objectClass=user))) and filters client-side.
// This is indistinguishable from -m users in ADWS logs / MDI telemetry.
// A targeted (servicePrincipalName=*) filter is logged verbatim by MDI
// and triggers "Possible SPN enumeration via ADWS".
func (e *Enumerator) Kerberoastable() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Kerberoastable users (via full user sweep, filtered client-side)")
	}

	all, err := e.runTargeted(userFilter, userAttrs, "kerberoastable")
	if err != nil {
		return nil, err
	}

	var out []adws.ADObject
	for _, obj := range all {
		sam := attrStr(obj, "sAMAccountName")
		// Skip krbtgt and machine accounts.
		if sam == "krbtgt" || strings.HasSuffix(sam, "$") {
			continue
		}
		// Skip disabled accounts.
		uac := parseInt(attrStr(obj, "userAccountControl"))
		if uac&uacDisabled != 0 {
			continue
		}
		// Keep only objects that actually have SPNs.
		if len(obj.Attributes["servicePrincipalName"]) == 0 {
			continue
		}
		out = append(out, obj)
	}
	return out, nil
}

// -------------------------------------------------------------------------
// AS-REP Roastable
// -------------------------------------------------------------------------

// ASREPRoastable returns enabled users with DONT_REQUIRE_PREAUTH set.
//
// OPSEC: Uses the full user sweep filter and filters client-side on the
// DONT_REQUIRE_PREAUTH UAC bit. Avoids a fingerprintable UAC bitmask
// extensible-match filter in the ADWS query log.
func (e *Enumerator) ASREPRoastable() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] AS-REP roastable users (via full user sweep, filtered client-side)")
	}

	all, err := e.runTargeted(userFilter, userAttrs, "asreproastable")
	if err != nil {
		return nil, err
	}

	var out []adws.ADObject
	for _, obj := range all {
		uac := parseInt(attrStr(obj, "userAccountControl"))
		if uac&uacDisabled != 0 {
			continue
		}
		if uac&uacDontReqPreauth != 0 {
			out = append(out, obj)
		}
	}
	return out, nil
}

// -------------------------------------------------------------------------
// Unconstrained Delegation
// -------------------------------------------------------------------------

var unconstrainedAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectClass",
	"dNSHostName",
	"objectSid",
	"userAccountControl",
	"operatingSystem",
	"lastLogon",
}

// UnconstrainedDelegation returns computers and users (non-DCs) with
// TRUSTED_FOR_DELEGATION set — any ticket arriving at these hosts
// can be forged by an attacker who compromises them.
func (e *Enumerator) UnconstrainedDelegation() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Unconstrained delegation")
	}

	// Computers (excluding DCs — they have it by design).
	compFilter := fmt.Sprintf("(&(objectClass=computer)%s%s"+
		"(!(primaryGroupID=%d))(!(primaryGroupID=%d)))",
		uacFilter(uacTrustedForDeleg), notDisabled(), uacDC, uacRODC)

	// Users with unconstrained delegation (rare, very suspicious).
	userFilter := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)%s%s)",
		uacFilter(uacTrustedForDeleg), notDisabled())

	comps, err := e.runTargeted(compFilter, unconstrainedAttrs, "unconstrained-computers")
	if err != nil {
		return nil, err
	}
	e.pace.BetweenRequests()

	users, err := e.runTargeted(userFilter, unconstrainedAttrs, "unconstrained-users")
	if err != nil {
		return nil, err
	}

	return append(comps, users...), nil
}

// -------------------------------------------------------------------------
// Constrained Delegation (classic + protocol transition)
// -------------------------------------------------------------------------

var constrainedAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectClass",
	"msDS-AllowedToDelegateTo",
	"userAccountControl",
	"servicePrincipalName",
}

// ConstrainedDelegation returns objects with msDS-AllowedToDelegateTo set.
// TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) on top = protocol-transition.
func (e *Enumerator) ConstrainedDelegation() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Constrained delegation")
	}

	filter := "(msDS-AllowedToDelegateTo=*)"
	return e.runTargeted(filter, constrainedAttrs, "constrained-delegation")
}

// -------------------------------------------------------------------------
// Resource-Based Constrained Delegation (RBCD)
// -------------------------------------------------------------------------

var rbcdAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectClass",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
	"userAccountControl",
}

// RBCD returns objects with msDS-AllowedToActOnBehalfOfOtherIdentity set —
// prime candidates for RBCD exploitation.
func (e *Enumerator) RBCD() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] RBCD candidates")
	}

	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	return e.runTargeted(filter, rbcdAttrs, "rbcd")
}

// -------------------------------------------------------------------------
// AdminSDHolder-protected accounts (adminCount=1)
// -------------------------------------------------------------------------

var adminCountAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectClass",
	"objectSid",
	"adminCount",
	"userAccountControl",
	"memberOf",
	"pwdLastSet",
	"lastLogon",
}

// AdminCount returns all objects with adminCount=1 (protected by AdminSDHolder).
// Includes disabled accounts — those are often forgotten but still dangerous.
func (e *Enumerator) AdminCount() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] AdminCount=1 objects")
	}

	filter := "(adminCount=1)"
	return e.runTargeted(filter, adminCountAttrs, "admincount")
}

// -------------------------------------------------------------------------
// Shadow Credentials
// -------------------------------------------------------------------------

var shadowCredAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"objectClass",
	"msDS-KeyCredentialLink",
	"userAccountControl",
}

// ShadowCredentials returns objects with msDS-KeyCredentialLink populated —
// attacker-written values here allow certificate-based auth as that object.
func (e *Enumerator) ShadowCredentials() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Shadow credentials")
	}

	filter := "(msDS-KeyCredentialLink=*)"
	return e.runTargeted(filter, shadowCredAttrs, "shadow-credentials")
}

// -------------------------------------------------------------------------
// LAPS
// -------------------------------------------------------------------------

var lapsAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"dNSHostName",
	"ms-Mcs-AdmPwd",         // legacy LAPS — readable if we have rights
	"ms-Mcs-AdmPwdExpirationTime",
	"msLAPS-Password",       // Windows LAPS (2023+)
	"msLAPS-PasswordExpirationTime",
	"userAccountControl",
}

// LAPS returns computers that have a LAPS-managed local admin password.
// If the caller has read rights, the password attribute will be populated.
func (e *Enumerator) LAPS() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] LAPS-managed computers")
	}

	// Try legacy LAPS attribute first, fall back to Windows LAPS.
	legacyFilter := "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))"
	newFilter := "(&(objectClass=computer)(msLAPS-Password=*))"

	legacy, err := e.runTargeted(legacyFilter, lapsAttrs, "laps-legacy")
	if err != nil {
		legacy = nil
	}
	e.pace.BetweenRequests()

	newLAPS, err := e.runTargeted(newFilter, lapsAttrs, "laps-new")
	if err != nil {
		newLAPS = nil
	}

	merged := dedupe(append(legacy, newLAPS...))
	if e.verbose {
		log.Printf("[+] LAPS computers: %d", len(merged))
	}
	return merged, nil
}

// -------------------------------------------------------------------------
// Password-never-expires
// -------------------------------------------------------------------------

var stalePassAttrs = []string{
	"sAMAccountName",
	"distinguishedName",
	"userAccountControl",
	"pwdLastSet",
	"lastLogon",
	"lastLogonTimestamp",
	"adminCount",
}

// PasswordNeverExpires returns enabled users whose passwords are set to
// never expire — frequently service accounts with weak/reused passwords.
func (e *Enumerator) PasswordNeverExpires() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Password-never-expires accounts")
	}

	filter := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)%s%s)",
		uacFilter(uacDontExpirePass), notDisabled())

	return e.runTargeted(filter, stalePassAttrs, "pwd-never-expires")
}

// -------------------------------------------------------------------------
// Stale accounts (no logon in N days)
// -------------------------------------------------------------------------

// StaleAccounts returns enabled users who haven't logged in for staledays.
// Uses lastLogonTimestamp (replicated) rather than lastLogon (per-DC).
func (e *Enumerator) StaleAccounts(staleDays int) ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Stale accounts (>%d days)", staleDays)
	}

	// lastLogonTimestamp is in Windows FILETIME (100-nanosecond intervals
	// since 1601-01-01). Convert our cutoff to that format.
	cutoff := time.Now().AddDate(0, 0, -staleDays)
	fileTime := toWindowsFileTime(cutoff)

	filter := fmt.Sprintf(
		"(&(objectCategory=person)(objectClass=user)%s(lastLogonTimestamp<=%d))",
		notDisabled(), fileTime)

	return e.runTargeted(filter, stalePassAttrs, "stale-accounts")
}

// toWindowsFileTime converts a Go time to Windows FILETIME.
func toWindowsFileTime(t time.Time) int64 {
	// Windows epoch: 1601-01-01T00:00:00Z
	winEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return t.UTC().Sub(winEpoch).Nanoseconds() / 100
}

// -------------------------------------------------------------------------
// Fine-grained password policies
// -------------------------------------------------------------------------

var fgppAttrs = []string{
	"name",
	"distinguishedName",
	"msDS-PasswordSettingsPrecedence",
	"msDS-MinimumPasswordLength",
	"msDS-PasswordHistoryLength",
	"msDS-PasswordComplexityEnabled",
	"msDS-LockoutThreshold",
	"msDS-LockoutObservationWindow",
	"msDS-LockoutDuration",
	"msDS-MaximumPasswordAge",
	"msDS-MinimumPasswordAge",
	"msDS-PSOAppliesTo",
}

// FineGrainedPasswordPolicies returns all PSOs in the domain.
// These often apply to privileged accounts with weaker lockout settings.
func (e *Enumerator) FineGrainedPasswordPolicies() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("[*] Fine-grained password policies")
	}

	psoDN := "CN=Password Settings Container,CN=System," + e.baseDN
	filter := "(objectClass=msDS-PasswordSettings)"

	return e.runTargetedScoped(psoDN, filter, fgppAttrs, adws.ScopeOneLevel, "fgpp")
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

// runTargeted is a convenience wrapper for targeted (small result set) queries.
// Uses a single pull with batchSize rather than a streaming channel, because
// targeted results are expected to be small and a single request is less noisy.
func (e *Enumerator) runTargeted(filter string, attrs []string, label string) ([]adws.ADObject, error) {
	return e.runTargetedScoped(e.baseDN, filter, attrs, adws.ScopeSubtree, label)
}

func (e *Enumerator) runTargetedScoped(
	baseDN, filter string,
	attrs []string,
	scope int,
	label string,
) ([]adws.ADObject, error) {
	results, err := e.client.Query(baseDN, filter, attrs, scope)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if e.verbose {
		log.Printf("[+] %s: %d", label, len(results))
	}
	return results, nil
}

// dedupe removes objects with duplicate distinguishedName values.
func dedupe(items []adws.ADObject) []adws.ADObject {
	seen := make(map[string]struct{}, len(items))
	out := items[:0]
	for _, item := range items {
		dn := attrStr(item, "distinguishedName")
		if _, exists := seen[dn]; exists {
			continue
		}
		seen[dn] = struct{}{}
		out = append(out, item)
	}
	return out
}

// AttrStr extracts the first string value of an attribute from an ADObject.
// Attributes is map[string][]ADWSValue — key is the attribute name.
func AttrStr(obj adws.ADObject, name string) string {
	vals, ok := obj.Attributes[name]
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0].Value
}

// attrStr is the package-private alias used within the enum package.
func attrStr(obj adws.ADObject, name string) string { return AttrStr(obj, name) }

// SIDStr returns the human-readable S-1-5-... SID for a given attribute.
// ADWS returns binary attributes as base64-encoded strings in Value when
// RawValue is not populated — so we try both.
func SIDStr(obj adws.ADObject, name string) string {
	vals, ok := obj.Attributes[name]
	if !ok || len(vals) == 0 {
		return ""
	}

	raw := vals[0].RawValue
	if len(raw) == 0 && vals[0].Value != "" {
		decoded, err := base64.StdEncoding.DecodeString(vals[0].Value)
		if err == nil {
			raw = decoded
		}
	}

	if len(raw) > 0 {
		return adws.ConvertSID(raw)
	}
	return vals[0].Value
}
