package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// ResolverOptions configures DNS resolution behaviour used for DC discovery
// and for dialling the ADWS TCP connection.
type ResolverOptions struct {
	// NameServer is an optional custom DNS server address (host or host:port).
	// If empty, the system resolver is used.
	NameServer string

	// UseTCP forces DNS queries to be sent over TCP instead of UDP.
	// Useful when UDP DNS is blocked, when large SRV responses are expected,
	// or when DNS-over-TCP is required by policy.
	// When NameServer is empty and UseTCP is true, the system-selected server
	// is still contacted but via TCP.
	UseTCP bool

	// DialContext, if non-nil, replaces net.Dialer.DialContext for the ADWS TCP
	// connection. Set this to a SOCKS5 dialer to route ADWS traffic via a proxy.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// buildResolver constructs a *net.Resolver from opts.
//
// Behaviour matrix:
//
//	NameServer=""  UseTCP=false  →  net.DefaultResolver (OS stub resolver)
//	NameServer=""  UseTCP=true   →  pure-Go resolver, TCP to system-chosen server
//	NameServer=X   UseTCP=false  →  pure-Go resolver, UDP  to X:53
//	NameServer=X   UseTCP=true   →  pure-Go resolver, TCP  to X:53
func buildResolver(opts ResolverOptions) *net.Resolver {
	if opts.NameServer == "" && !opts.UseTCP {
		return net.DefaultResolver
	}

	// Normalise nameserver: add :53 if no port is specified.
	ns := opts.NameServer
	if ns != "" {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			// SplitHostPort failed → no port present.
			ns = net.JoinHostPort(ns, "53")
		}
	}

	network := "udp"
	if opts.UseTCP {
		network = "tcp"
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, address string) (net.Conn, error) {
			// address is the server the Go resolver would normally contact.
			// Override it with ns when a custom server was requested; otherwise
			// forward to the system-chosen address but over TCP.
			target := address
			if ns != "" {
				target = ns
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
}

// ResolveIPToFQDN returns the FQDN for host by performing a reverse DNS (PTR)
// lookup when host is an IP address, and returns host unchanged otherwise.
//
// The first hostname returned by the PTR lookup is used. A trailing dot
// (canonical DNS form) is stripped automatically. If the lookup fails the
// error is returned so the caller can decide whether to fall back to the raw IP.
func ResolveIPToFQDN(ctx context.Context, host string, opts ResolverOptions) (string, error) {
	if net.ParseIP(host) == nil {
		return host, nil
	}

	resolver := buildResolver(opts)
	names, err := resolver.LookupAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("reverse lookup of %s: %w", host, err)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("reverse lookup of %s: no PTR records found", host)
	}

	// Strip trailing dot from canonical DNS name.
	fqdn := names[0]
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '.' {
		fqdn = fqdn[:len(fqdn)-1]
	}
	return fqdn, nil
}

// DiscoverDC finds a domain controller for domain by querying SRV records.
//
// It queries (in order):
//
//	_ldap._tcp.<domain>
//	_kerberos._tcp.<domain>
//
// The target of the first record (sorted by priority then weight, as returned
// by net.Resolver.LookupSRV) is returned. An error is returned when no SRV
// records are found for either service.
//
// opts controls which DNS server and transport protocol are used for the lookup.
func DiscoverDC(ctx context.Context, domain string, opts ResolverOptions) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("DC discovery: domain must not be empty")
	}

	resolver := buildResolver(opts)

	for _, service := range []string{"ldap", "kerberos"} {
		_, addrs, err := resolver.LookupSRV(ctx, service, "tcp", domain)
		if err != nil || len(addrs) == 0 {
			continue
		}
		// LookupSRV returns records sorted by priority (ascending) then weight
		// (descending). The first element is therefore the preferred target.
		target := addrs[0].Target
		// DNS FQDNs often have a trailing dot; strip it.
		if len(target) > 0 && target[len(target)-1] == '.' {
			target = target[:len(target)-1]
		}
		return target, nil
	}

	return "", fmt.Errorf(
		"no SRV records found for domain %q (tried _ldap._tcp and _kerberos._tcp)",
		domain,
	)
}

// DialADWS dials a TCP connection to the ADWS port on host and returns the raw
// net.Conn. The returned connection should be passed to NewNNSConnection (or one
// of its variants) and then to NewNMFConnection.
//
// Name resolution uses the resolver built from opts, so a custom DNS server and
// DNS-over-TCP are honoured consistently for both discovery and dialling.
//
// If port is 0, the default ADWS port 9389 is used.
func DialADWS(ctx context.Context, host string, port int, opts ResolverOptions) (net.Conn, error) {
	if port == 0 {
		port = 9389
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialFn := opts.DialContext
	if dialFn == nil {
		d := &net.Dialer{Resolver: buildResolver(opts)}
		dialFn = d.DialContext
	}

	conn, err := dialFn(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial ADWS %s: %w", address, err)
	}

	return conn, nil
}
