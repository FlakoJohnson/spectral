// Package recon provides unauthenticated pre-credential reconnaissance.
package recon

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/net/proxy"
)

// RootDSE holds the parsed attributes from an anonymous rootDSE query.
type RootDSE struct {
	DefaultNamingContext  string              `json:"default_naming_context"`
	ConfigurationNC       string              `json:"configuration_nc"`
	SchemaNamingContext   string              `json:"schema_nc"`
	RootDomainNC          string              `json:"root_domain_nc"`
	DNSHostName           string              `json:"dns_host_name"`
	ServerName            string              `json:"server_name"`
	DomainFunctionality   string              `json:"domain_functionality"`
	ForestFunctionality   string              `json:"forest_functionality"`
	DCFunctionality       string              `json:"dc_functionality"`
	SupportedLDAPVersions []string            `json:"supported_ldap_versions"`
	SupportedSASL         []string            `json:"supported_sasl_mechanisms"`
	CurrentTime           string              `json:"current_time"`
	HighestCommittedUSN   string              `json:"highest_committed_usn"`
	Raw                   map[string][]string `json:"raw"`
}

var rootDSEAttrs = []string{
	"defaultNamingContext",
	"configurationNamingContext",
	"schemaNamingContext",
	"rootDomainNamingContext",
	"dnsHostName",
	"serverName",
	"domainFunctionality",
	"forestFunctionality",
	"domainControllerFunctionality",
	"supportedLDAPVersion",
	"supportedSASLMechanisms",
	"supportedCapabilities",
	"currentTime",
	"highestCommittedUSN",
}

// dialTimeout is the per-attempt TCP connect timeout.
const dialTimeout = 4 * time.Second

// QueryRootDSE performs an anonymous LDAP query against the rootDSE.
// No credentials required — readable by default on all AD DCs.
// proxyURL, if non-empty, routes the TCP connection through a SOCKS5 proxy
// (e.g. "socks5://127.0.0.1:1080"). When proxyURL is empty the system
// resolver is used and port 389 falls back to LDAPS/636 on failure.
func QueryRootDSE(target, port, proxyURL string) (*RootDSE, error) {
	if port == "" {
		port = "389"
	}

	conn, err := dialLDAP(target, port, proxyURL)
	if err != nil && port == "389" {
		// Port 389 may be blocked — try LDAPS on 636 as fallback.
		conn, err = dialLDAPS(target, "636", proxyURL)
		if err != nil {
			return nil, fmt.Errorf("port 389 and LDAPS 636 both unreachable on %s", target)
		}
	} else if err != nil {
		return nil, fmt.Errorf("dial %s:%s: %w", target, port, err)
	}
	defer conn.Close()

	// Anonymous bind — no credentials.
	if err := conn.UnauthenticatedBind(""); err != nil {
		return nil, fmt.Errorf("anonymous bind: %w", err)
	}

	req := ldap.NewSearchRequest(
		"", // empty base = rootDSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		rootDSEAttrs,
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("rootDSE search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no rootDSE returned (target may not be an AD DC)")
	}

	entry := res.Entries[0]
	dse := &RootDSE{Raw: make(map[string][]string)}

	for _, attr := range entry.Attributes {
		dse.Raw[attr.Name] = attr.Values
		first := ""
		if len(attr.Values) > 0 {
			first = attr.Values[0]
		}
		switch attr.Name {
		case "defaultNamingContext":
			dse.DefaultNamingContext = first
		case "configurationNamingContext":
			dse.ConfigurationNC = first
		case "schemaNamingContext":
			dse.SchemaNamingContext = first
		case "rootDomainNamingContext":
			dse.RootDomainNC = first
		case "dnsHostName":
			dse.DNSHostName = first
		case "serverName":
			dse.ServerName = first
		case "domainFunctionality":
			dse.DomainFunctionality = functionalityLabel(first)
		case "forestFunctionality":
			dse.ForestFunctionality = functionalityLabel(first)
		case "domainControllerFunctionality":
			dse.DCFunctionality = functionalityLabel(first)
		case "supportedLDAPVersion":
			dse.SupportedLDAPVersions = attr.Values
		case "supportedSASLMechanisms":
			dse.SupportedSASL = attr.Values
		case "currentTime":
			dse.CurrentTime = first
		case "highestCommittedUSN":
			dse.HighestCommittedUSN = first
		}
	}

	return dse, nil
}

// dialLDAP opens a plain LDAP connection, optionally via a SOCKS5 proxy.
func dialLDAP(target, port, proxyURL string) (*ldap.Conn, error) {
	if proxyURL != "" {
		return dialViaProxy(target, port, proxyURL, false)
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return ldap.DialURL(
		fmt.Sprintf("ldap://%s:%s", target, port),
		ldap.DialWithDialer(d),
	)
}

// dialLDAPS opens an LDAPS connection, optionally via a SOCKS5 proxy.
// InsecureSkipVerify is acceptable here because rootDSE is anonymous and read-only.
func dialLDAPS(target, port, proxyURL string) (*ldap.Conn, error) {
	if proxyURL != "" {
		return dialViaProxy(target, port, proxyURL, true)
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return ldap.DialURL(
		fmt.Sprintf("ldaps://%s:%s", target, port),
		ldap.DialWithDialer(d),
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec
	)
}

// dialViaProxy creates a TCP connection through a SOCKS5 proxy, then wraps it
// with optional TLS and hands it to the LDAP library via ldap.NewConn.
func dialViaProxy(target, port, proxyURL string, useTLS bool) (*ldap.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("proxy URL: %w", err)
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("proxy dialer: %w", err)
	}

	addr := target + ":" + port
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial %s: %w", addr, err)
	}

	if useTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: true, ServerName: target} //nolint:gosec
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake via proxy: %w", err)
		}
		l := ldap.NewConn(tlsConn, true)
		l.Start()
		return l, nil
	}

	l := ldap.NewConn(conn, false)
	l.Start()
	return l, nil
}

// functionalityLabel maps AD functional level integers to readable strings.
func functionalityLabel(level string) string {
	labels := map[string]string{
		"0":  "Windows 2000",
		"1":  "Windows Server 2003 Mixed",
		"2":  "Windows Server 2003",
		"3":  "Windows Server 2008",
		"4":  "Windows Server 2008 R2",
		"5":  "Windows Server 2012",
		"6":  "Windows Server 2012 R2",
		"7":  "Windows Server 2016/2019/2022",
		"10": "Windows Server 2025",
	}
	if label, ok := labels[level]; ok {
		return fmt.Sprintf("%s (%s)", level, label)
	}
	return level
}
