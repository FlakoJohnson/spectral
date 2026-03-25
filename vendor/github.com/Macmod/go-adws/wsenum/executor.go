package wsenum

import (
	"fmt"
	"strings"

	soap "github.com/Macmod/go-adws/soap"
)

// ValidateQueryInput normalises and validates the baseDN, filter, attrs, and scope
// before an enumeration query. It trims whitespace, defaults an empty filter to
// "(objectClass=*)", rejects out-of-range scope values, and ensures distinguishedName
// is always included in the attribute list.
func ValidateQueryInput(baseDN, filter string, attrs []string, scope int) (string, string, []string, error) {
	baseDN = strings.TrimSpace(baseDN)
	if baseDN == "" {
		return "", "", nil, fmt.Errorf("baseDN is required")
	}

	filter = strings.TrimSpace(filter)
	if filter == "" {
		filter = "(objectClass=*)"
	}

	if scope < 0 || scope > 2 {
		return "", "", nil, fmt.Errorf("invalid scope %d (valid: 0=Base, 1=OneLevel, 2=Subtree)", scope)
	}

	hasDN := false
	for _, attr := range attrs {
		if strings.EqualFold(attr, "distinguishedName") {
			hasDN = true
			break
		}
	}
	if !hasDN {
		attrs = append(attrs, "distinguishedName")
	}

	return baseDN, filter, attrs, nil
}

// ExecuteQuery runs an Enumerate + Pull loop against service.
// When batchChannel is non-nil, each Pull batch is sent to the channel and allItems
// is returned as nil (streaming mode); otherwise all items are accumulated and returned.
func ExecuteQuery(service *WSEnumClient, baseDN, filter string, attrs []string, scope, maxElementsPerPull, defaultMaxElementsPerPull int, batchChannel chan<- []soap.ADWSItem) ([]soap.ADWSItem, error) {
	if maxElementsPerPull <= 0 {
		maxElementsPerPull = defaultMaxElementsPerPull
	}

	enumResp, err := service.Enumerate(baseDN, filter, attrs, scope)
	if err != nil {
		return nil, err
	}

	if enumResp.EndOfSequence {
		return []soap.ADWSItem{}, nil
	}

	var allItems []soap.ADWSItem
	ctx := enumResp.EnumerationContext

	for ctx != "" {
		pr, err := service.Pull(ctx, maxElementsPerPull, 0)
		if err != nil {
			return nil, err
		}

		if batchChannel != nil {
			if len(pr.Items) > 0 {
				batch := make([]soap.ADWSItem, len(pr.Items))
				copy(batch, pr.Items)
				batchChannel <- batch
			}
		} else {
			allItems = append(allItems, pr.Items...)
		}

		if pr.EndOfSequence {
			break
		}
		if pr.EnumerationContext == "" {
			return nil, fmt.Errorf("invalid Pull response: missing EnumerationContext without EndOfSequence")
		}
		ctx = pr.EnumerationContext
	}

	if batchChannel != nil {
		return nil, nil
	}
	return allItems, nil
}
