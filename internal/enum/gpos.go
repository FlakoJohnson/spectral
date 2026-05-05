package enum

import (
	"fmt"
	"log"
	"strings"

	"spectral/internal/adws"
)

// OPSEC: Target the CN=Policies container directly for GPOs —
// a scoped query rather than a domain-wide sweep.
const gpoFilter = "(objectClass=groupPolicyContainer)"

// OPSEC: WMI filters use specific container to avoid broad queries
const wmiFilterFilter = "(objectClass=msWMI-Som)"

// OPSEC: Site queries target configuration partition to avoid domain enumeration
const siteFilter = "(objectClass=site)"

// GPOs enumerates Group Policy Objects.
func (e *Enumerator) GPOs() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating GPOs", ts())
	}

	gpoDN := "CN=Policies,CN=System," + e.domainDN

	results, err := e.queryWithRetry(gpoDN, gpoFilter, gpoAttrs, 7, nil)
	if err != nil {
		if e.verbose {
			log.Printf("%s [*] GPO container fallback to domain scope", ts())
		}
		results, err = e.queryWithRetry(e.domainDN, gpoFilter, gpoAttrs, 7, nil)
		if err != nil {
			return nil, err
		}
	}

	if e.verbose {
		log.Printf("%s [+] GPOs: %d", ts(), len(results))
	}
	return results, nil
}

// GPOsEnhanced enumerates GPOs with comprehensive metadata for deep analysis
// OPSEC: Uses randomized batch sizes and delays between attribute requests
func (e *Enumerator) GPOsEnhanced() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating GPOs (enhanced metadata)", ts())
	}

	gpoDN := "CN=Policies,CN=System," + e.domainDN

	// OPSEC: Split into multiple queries to avoid large attribute requests
	// Query basic attributes first
	results, err := e.queryWithRetry(gpoDN, gpoFilter, gpoAttrs, 7, nil)
	if err != nil {
		if e.verbose {
			log.Printf("%s [*] GPO container fallback to domain scope", ts())
		}
		results, err = e.queryWithRetry(e.domainDN, gpoFilter, gpoAttrs, 7, nil)
		if err != nil {
			return nil, err
		}
	}

	// Query enhanced attributes separately to reduce per-query footprint
	enhancedResults, err := e.queryWithRetry(gpoDN, gpoFilter, gpoEnhancedAttrs, 7,
		func(batch []adws.ADObject) error {
			// OPSEC: Add delay between queries to avoid rapid-fire pattern
			e.pace.BetweenRequests()
			return nil
		})
	if err == nil {
		// Merge enhanced attributes into basic results
		results = e.mergeGPOAttributes(results, enhancedResults)
	}

	if e.verbose {
		log.Printf("%s [+] Enhanced GPOs: %d", ts(), len(results))
	}
	return results, nil
}

// WMIFilters enumerates WMI filters linked to GPOs
// OPSEC: Targets specific container, uses minimal attributes to reduce noise
func (e *Enumerator) WMIFilters() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating WMI Filters", ts())
	}

	// OPSEC: Target WMI container directly - most scanners skip this
	wmiDN := "CN=SOM,CN=WMIPolicy,CN=System," + e.domainDN

	results, err := e.queryWithRetry(wmiDN, wmiFilterFilter, wmiFilterAttrs, 7, nil)
	if err != nil {
		// Fallback to system container scope
		systemDN := "CN=System," + e.domainDN
		results, err = e.queryWithRetry(systemDN, wmiFilterFilter, wmiFilterAttrs, 7, nil)
		if err != nil {
			if e.verbose {
				log.Printf("%s [!] WMI Filters enumeration failed: %v", ts(), err)
			}
			return nil, err
		}
	}

	if e.verbose {
		log.Printf("%s [+] WMI Filters: %d", ts(), len(results))
	}
	return results, nil
}

// SiteGPOLinks enumerates site-level GPO links - often missed by tools
// OPSEC: Queries configuration partition, avoids domain controller enumeration
func (e *Enumerator) SiteGPOLinks() ([]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating site GPO links", ts())
	}

	// OPSEC: Query configuration partition directly
	configDN := e.getConfigurationDN()
	sitesDN := "CN=Sites," + configDN

	results, err := e.queryWithRetry(sitesDN, siteFilter, siteAttrs, 7, nil)
	if err != nil {
		if e.verbose {
			log.Printf("%s [!] Site enumeration failed: %v", ts(), err)
		}
		return nil, err
	}

	// OPSEC: Filter only sites with GPO links to reduce noise
	linkedSites := e.filterSitesWithGPOLinks(results)

	if e.verbose {
		log.Printf("%s [+] Sites with GPO links: %d", ts(), len(linkedSites))
	}
	return linkedSites, nil
}

// mergeGPOAttributes combines basic and enhanced GPO attribute results
// OPSEC: Reduces query complexity by splitting attribute requests
func (e *Enumerator) mergeGPOAttributes(basic, enhanced []adws.ADObject) []adws.ADObject {
	enhancedMap := make(map[string]adws.ADObject)

	// Index enhanced results by DN
	for _, obj := range enhanced {
		dn := AttrStr(obj, "distinguishedName")
		enhancedMap[dn] = obj
	}

	// Merge enhanced attributes into basic objects
	for i, basicObj := range basic {
		dn := AttrStr(basicObj, "distinguishedName")
		if enhancedObj, exists := enhancedMap[dn]; exists {
			// Copy additional attributes from enhanced query
			for key, value := range enhancedObj.Attributes {
				if _, hasKey := basicObj.Attributes[key]; !hasKey {
					basic[i].Attributes[key] = value
				}
			}
		}
	}

	return basic
}

// getConfigurationDN derives the configuration partition DN from domain DN
// OPSEC: Avoids additional rootDSE queries when possible
func (e *Enumerator) getConfigurationDN() string {
	// Convert DC=domain,DC=com -> CN=Configuration,DC=domain,DC=com
	parts := strings.Split(e.domainDN, ",")
	configDN := "CN=Configuration"
	for _, part := range parts {
		if strings.HasPrefix(part, "DC=") {
			configDN += "," + part
		}
	}
	return configDN
}

// filterSitesWithGPOLinks returns only sites that have actual GPO links
// OPSEC: Reduces result set size and avoids returning empty site objects
func (e *Enumerator) filterSitesWithGPOLinks(sites []adws.ADObject) []adws.ADObject {
	var linkedSites []adws.ADObject

	for _, site := range sites {
		gPLink := AttrStr(site, "gPLink")
		// Only include sites with actual GPO links
		if gPLink != "" && gPLink != " " {
			linkedSites = append(linkedSites, site)
		}
	}

	return linkedSites
}

// CrossDomainGPOs enumerates GPOs from trusted domains for forest-wide analysis
// OPSEC: Uses trust relationships to avoid broad forest enumeration
func (e *Enumerator) CrossDomainGPOs(trustedDomains []string) (map[string][]adws.ADObject, error) {
	if e.verbose {
		log.Printf("%s [*] Enumerating cross-domain GPOs", ts())
	}

	crossDomainGPOs := make(map[string][]adws.ADObject)

	for _, domain := range trustedDomains {
		domainDN := e.domainToDN(domain)
		gpoDN := "CN=Policies,CN=System," + domainDN

		results, err := e.queryWithRetry(gpoDN, gpoFilter, gpoAttrs, 7,
			func(batch []adws.ADObject) error {
				// OPSEC: Add randomized delay between domain queries
				e.pace.BetweenRequests()
				return nil
			})
		if err != nil {
			if e.verbose {
				log.Printf("%s [!] Failed to enumerate GPOs from %s: %v", ts(), domain, err)
			}
			continue
		}

		crossDomainGPOs[domain] = results
		if e.verbose {
			log.Printf("%s [+] GPOs from %s: %d", ts(), domain, len(results))
		}
	}

	return crossDomainGPOs, nil
}

// domainToDN converts FQDN to distinguished name
func (e *Enumerator) domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dn := ""
	for i, part := range parts {
		if i > 0 {
			dn += ","
		}
		dn += fmt.Sprintf("DC=%s", part)
	}
	return dn
}
