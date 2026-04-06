// Package adws wraps github.com/Macmod/sopa with OPSEC-aware defaults.
package adws

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	sopa "github.com/Macmod/sopa"
	sopatransport "github.com/Macmod/go-adws/transport"
	"golang.org/x/net/proxy"
)

const (
	ScopeBase     = 0
	ScopeOneLevel = 1
	ScopeSubtree  = 2
)

// Config holds connection parameters.
type Config struct {
	Target   string
	Port     string
	Domain   string
	Username string
	Password string
	NTHash   string
	CCache   string
	Kerberos bool
	DebugXML bool
	// ProxyURL routes all ADWS TCP traffic through a SOCKS5 proxy.
	// Format: "socks5://host:port"  (e.g. "socks5://127.0.0.1:1080")
	ProxyURL string
}

// Client wraps sopa.WSClient with auto-reconnect on broken connections.
type Client struct {
	inner *sopa.WSClient
	cfg   Config
}

// ADObject is a single LDAP object returned from a query.
type ADObject = sopa.ADWSItem

// NewClient initialises a client from Config.
func NewClient(cfg Config) (*Client, error) {
	inner, err := buildInner(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner, cfg: cfg}, nil
}

func buildInner(cfg Config) (*sopa.WSClient, error) {
	port := 9389
	if cfg.Port != "" {
		if p, err := fmt.Sscanf(cfg.Port, "%d", &port); p == 0 || err != nil {
			port = 9389
		}
	}

	var dialFn func(ctx context.Context, network, addr string) (net.Conn, error)
	if cfg.ProxyURL != "" {
		u, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("proxy URL: %w", err)
		}
		d, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("proxy dialer: %w", err)
		}
		dialFn = func(_ context.Context, network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}
	}

	return sopa.NewWSClient(sopa.Config{
		DCAddr:      cfg.Target,
		Port:        port,
		Domain:      cfg.Domain,
		Username:    cfg.Username,
		Password:    cfg.Password,
		NTHash:      cfg.NTHash,
		CCachePath:  cfg.CCache,
		UseKerberos: cfg.Kerberos || cfg.CCache != "",
		DebugXML:    cfg.DebugXML,
		ResolverOptions: sopatransport.ResolverOptions{
			DialContext: dialFn,
		},
	})
}

func ts() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05 UTC --")
}

// isBrokenPipe returns true if the error indicates a dead TCP connection.
func isBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "connection timed out") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "EOF")
}

// reconnect tears down the old session and establishes a new one.
func (c *Client) reconnect() error {
	log.Printf("%s [*] Connection lost — reconnecting to %s:%s...", ts(), c.cfg.Target, c.cfg.Port)
	_ = c.inner.Close()

	// Brief cooldown before reconnecting
	time.Sleep(3 * time.Second)

	inner, err := buildInner(c.cfg)
	if err != nil {
		return fmt.Errorf("reconnect build: %w", err)
	}
	if err := inner.Connect(); err != nil {
		return fmt.Errorf("reconnect: %w", err)
	}
	c.inner = inner
	log.Printf("%s [+] Reconnected to %s:%s", ts(), c.cfg.Target, c.cfg.Port)
	return nil
}

// Connect establishes the ADWS TCP+NMF+NNS session.
func (c *Client) Connect() error {
	return c.inner.Connect()
}

// Close tears down the session.
func (c *Client) Close() error {
	return c.inner.Close()
}

// Query runs an LDAP search via ADWS. Auto-reconnects on broken pipe.
func (c *Client) Query(baseDN, filter string, attrs []string, scope int) ([]ADObject, error) {
	result, err := c.inner.Query(baseDN, filter, attrs, scope)
	if err != nil && isBrokenPipe(err) {
		if rerr := c.reconnect(); rerr != nil {
			return nil, fmt.Errorf("query failed and reconnect failed: %w (original: %v)", rerr, err)
		}
		// Retry once after reconnect
		return c.inner.Query(baseDN, filter, attrs, scope)
	}
	return result, err
}

// QueryBatched is like Query but invokes callback per batch, allowing
// the caller to pace between pages. Auto-reconnects on broken pipe.
func (c *Client) QueryBatched(
	baseDN, filter string,
	attrs []string,
	scope, batchSize int,
	callback func([]ADObject) error,
) error {
	err := c.queryBatchedInner(baseDN, filter, attrs, scope, batchSize, callback)
	if err != nil && isBrokenPipe(err) {
		if rerr := c.reconnect(); rerr != nil {
			return fmt.Errorf("batch query failed and reconnect failed: %w (original: %v)", rerr, err)
		}
		// Retry once after reconnect
		return c.queryBatchedInner(baseDN, filter, attrs, scope, batchSize, callback)
	}
	return err
}

func (c *Client) queryBatchedInner(
	baseDN, filter string,
	attrs []string,
	scope, batchSize int,
	callback func([]ADObject) error,
) error {
	ch := make(chan []ADObject, 4)
	errCh := make(chan error, 1)

	go func() {
		err := c.inner.QueryWithBatchChannel(baseDN, filter, attrs, scope, batchSize, ch)
		close(ch)
		errCh <- err
	}()

	for batch := range ch {
		if err := callback(batch); err != nil {
			return err
		}
	}

	return <-errCh
}

// QueryWithSDFlags runs an LDAP search with LDAP_SERVER_SD_FLAGS_OID control.
// sdFlags=7 requests OWNER + GROUP + DACL security information.
// This enables reading nTSecurityDescriptor even as a standard user.
func (c *Client) QueryWithSDFlags(baseDN, filter string, attrs []string, scope, sdFlags int) ([]ADObject, error) {
	result, err := c.queryWithSD(baseDN, filter, attrs, scope, sdFlags)
	if err != nil && isBrokenPipe(err) {
		if rerr := c.reconnect(); rerr != nil {
			return nil, fmt.Errorf("query failed and reconnect failed: %w (original: %v)", rerr, err)
		}
		return c.queryWithSD(baseDN, filter, attrs, scope, sdFlags)
	}
	return result, err
}

func (c *Client) queryWithSD(baseDN, filter string, attrs []string, scope, sdFlags int) ([]ADObject, error) {
	return c.inner.QueryWithSDFlags(baseDN, filter, attrs, scope, sdFlags)
}

// ConvertSID converts a raw binary SID to S-1-5-21-... string format.
func ConvertSID(b []byte) string {
	s, err := sopa.ConvertSIDBytes(b)
	if err != nil {
		return ""
	}
	return s
}

// GetDomain returns high-level domain metadata via MS-ADCAP.
func (c *Client) GetDomain() (*sopa.ADCAPActiveDirectoryDomain, error) {
	result, err := c.inner.ADCAPGetADDomain()
	if err != nil && isBrokenPipe(err) {
		if rerr := c.reconnect(); rerr != nil {
			return nil, rerr
		}
		return c.inner.ADCAPGetADDomain()
	}
	return result, err
}

// GetForest returns forest metadata via MS-ADCAP.
func (c *Client) GetForest() (*sopa.ADCAPActiveDirectoryForest, error) {
	result, err := c.inner.ADCAPGetADForest()
	if err != nil && isBrokenPipe(err) {
		if rerr := c.reconnect(); rerr != nil {
			return nil, rerr
		}
		return c.inner.ADCAPGetADForest()
	}
	return result, err
}
