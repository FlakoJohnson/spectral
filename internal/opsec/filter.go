package opsec

import (
	"math/rand"
	"strings"
	"unicode"
)

// ShuffleAttrs returns a shuffled copy of the attribute list.
// LDAP attribute order is irrelevant to AD, but static ordering
// creates a fingerprintable pattern in ADWS request payloads.
func ShuffleAttrs(attrs []string) []string {
	out := make([]string, len(attrs))
	copy(out, attrs)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// ShuffleFilter takes a compound LDAP filter like (&(A)(B)(C))
// and returns it with the inner clauses in random order.
// Supports & and | operators. Leaves non-compound filters unchanged.
func ShuffleFilter(filter string) string {
	filter = strings.TrimSpace(filter)
	if len(filter) < 4 {
		return filter
	}

	// Must start with ( and end with )
	if filter[0] != '(' || filter[len(filter)-1] != ')' {
		return filter
	}

	inner := filter[1 : len(filter)-1]
	if len(inner) == 0 {
		return filter
	}

	// Check for compound operator (& or |)
	op := inner[0]
	if op != '&' && op != '|' {
		return filter
	}

	// Parse child clauses by counting parenthesis depth
	clauses := parseClauses(inner[1:])
	if len(clauses) <= 1 {
		return filter
	}

	// Shuffle the clauses
	rand.Shuffle(len(clauses), func(i, j int) { clauses[i], clauses[j] = clauses[j], clauses[i] })

	var b strings.Builder
	b.WriteByte('(')
	b.WriteByte(op)
	for _, c := range clauses {
		b.WriteString(c)
	}
	b.WriteByte(')')
	return b.String()
}

// parseClauses splits a string of concatenated LDAP filter clauses
// like "(A)(B)(C)" into individual clauses ["(A)", "(B)", "(C)"].
// Handles nested parentheses correctly.
func parseClauses(s string) []string {
	var clauses []string
	depth := 0
	start := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				clauses = append(clauses, s[start:i+1])
				start = -1
			}
		}
	}
	return clauses
}

// MutateFilterCase randomly changes the case of LDAP attribute names
// in a filter string. LDAP attribute names are case-insensitive per
// RFC 4512, so (objectClass=user) and (OBJECTCLASS=user) are identical.
//
// Only mutates attribute names (left side of =), not values.
func MutateFilterCase(filter string) string {
	var b strings.Builder
	b.Grow(len(filter))
	inAttr := false

	for i := 0; i < len(filter); i++ {
		ch := filter[i]
		switch {
		case ch == '(':
			b.WriteByte(ch)
			// Check if this is a negation or operator
			if i+1 < len(filter) && (filter[i+1] == '!' || filter[i+1] == '&' || filter[i+1] == '|') {
				// Skip — not an attribute
			} else {
				inAttr = true
			}
		case ch == '=' || ch == '<' || ch == '>' || ch == '~':
			inAttr = false
			b.WriteByte(ch)
		case ch == ')':
			inAttr = false
			b.WriteByte(ch)
		case inAttr && unicode.IsLetter(rune(ch)):
			// Randomly flip case of attribute name characters
			if rand.Intn(3) == 0 { // ~33% chance per character
				if unicode.IsUpper(rune(ch)) {
					b.WriteByte(byte(unicode.ToLower(rune(ch))))
				} else {
					b.WriteByte(byte(unicode.ToUpper(rune(ch))))
				}
			} else {
				b.WriteByte(ch)
			}
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// Obfuscate applies both shuffle and case mutation to a compound filter.
func Obfuscate(filter string) string {
	return MutateFilterCase(ShuffleFilter(filter))
}

// PickVariant randomly selects one of the provided filter variants.
func PickVariant(variants ...string) string {
	return variants[rand.Intn(len(variants))]
}

// RandomBatch returns a random batch size in [min, max].
func RandomBatch(min, max int) int {
	if min >= max {
		return min
	}
	return min + rand.Intn(max-min+1)
}
