//go:build ignore

// apply.go patches two files in the vendored go-adws module to add DialContext
// support to ResolverOptions, enabling native SOCKS5 proxy routing.
//
// Run after `go mod vendor`:
//
//	go run patches/apply.go
package main

import (
	"fmt"
	"os"
	"strings"
)

const base = "vendor/github.com/Macmod/go-adws/transport/"

func main() {
	patchResolver()
	patchNNS()
}

func patchResolver() {
	path := base + "resolver.go"
	data := must(os.ReadFile(path))
	src := strings.ReplaceAll(string(data), "\r\n", "\n")

	// 1. Add DialContext field to ResolverOptions struct.
	const oldStruct = `	// When NameServer is empty and UseTCP is true, the system-selected server
	// is still contacted but via TCP.
	UseTCP bool
}`
	const newStruct = `	// When NameServer is empty and UseTCP is true, the system-selected server
	// is still contacted but via TCP.
	UseTCP bool

	// DialContext, if non-nil, replaces net.Dialer.DialContext for the ADWS TCP
	// connection. Set this to a SOCKS5 dialer to route ADWS traffic via a proxy.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}`
	src = replace(path, src, oldStruct, newStruct)

	// 2. Use DialContext in DialADWS when set.
	const oldDial = `	dialer := &net.Dialer{
		Resolver: buildResolver(opts),
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)`
	const newDial = `	dialFn := opts.DialContext
	if dialFn == nil {
		d := &net.Dialer{Resolver: buildResolver(opts)}
		dialFn = d.DialContext
	}

	conn, err := dialFn(ctx, "tcp", address)`
	src = replace(path, src, oldDial, newDial)

	write(path, src)
}

func patchNNS() {
	path := base + "nns.go"
	data := must(os.ReadFile(path))
	src := strings.ReplaceAll(string(data), "\r\n", "\n")

	// Update kdcDialer.Dial to use DialContext when set.
	const oldDial = `func (d kdcDialer) Dial(network, address string) (net.Conn, error) {
	// client.KDCDialer has no context parameter, so context.Background() is the
	// only option here. Cancellation of KDC exchanges must be handled by the
	// gokrb5 client itself via its own deadline/timeout configuration.
	dialer := &net.Dialer{Resolver: buildResolver(d.opts)}
	return dialer.DialContext(context.Background(), network, address)
}`
	const newDial = `func (d kdcDialer) Dial(network, address string) (net.Conn, error) {
	if d.opts.DialContext != nil {
		return d.opts.DialContext(context.Background(), network, address)
	}
	dialer := &net.Dialer{Resolver: buildResolver(d.opts)}
	return dialer.DialContext(context.Background(), network, address)
}`
	src = replace(path, src, oldDial, newDial)

	write(path, src)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func replace(path, src, old, new string) string {
	if !strings.Contains(src, old) {
		fmt.Fprintf(os.Stderr, "[-] patch target not found in %s\n    looking for:\n%s\n", path, old)
		os.Exit(1)
	}
	return strings.Replace(src, old, new, 1)
}

func write(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[-] write %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("[+] patched %s\n", path)
}

func must(b []byte, err error) []byte {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	return b
}
