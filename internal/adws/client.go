// Package adws wraps github.com/Macmod/sopa with OPSEC-aware defaults.
package adws

import (
	"fmt"

	sopa "github.com/Macmod/sopa"
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
}

// Client wraps sopa.WSClient.
type Client struct {
	inner *sopa.WSClient
}

// ADObject is a single LDAP object returned from a query.
type ADObject = sopa.ADWSItem

// NewClient initialises a client from Config.
func NewClient(cfg Config) (*Client, error) {
	port := 9389
	if cfg.Port != "" {
		if p, err := fmt.Sscanf(cfg.Port, "%d", &port); p == 0 || err != nil {
			port = 9389
		}
	}

	inner, err := sopa.NewWSClient(sopa.Config{
		DCAddr:      cfg.Target,
		Port:        port,
		Domain:      cfg.Domain,
		Username:    cfg.Username,
		Password:    cfg.Password,
		NTHash:      cfg.NTHash,
		CCachePath:  cfg.CCache,
		UseKerberos: cfg.Kerberos || cfg.CCache != "",
		DebugXML:    cfg.DebugXML,
	})
	if err != nil {
		return nil, err
	}

	return &Client{inner: inner}, nil
}

// Connect establishes the ADWS TCP+NMF+NNS session.
func (c *Client) Connect() error {
	return c.inner.Connect()
}

// Close tears down the session.
func (c *Client) Close() error {
	return c.inner.Close()
}

// Query runs an LDAP search via ADWS.
//
// OPSEC notes baked in:
//   - Callers should use specific objectClass/objectCategory filters
//     rather than generic catch-alls like (!FALSE).
//   - Attribute lists should be minimal — only request what is needed.
func (c *Client) Query(baseDN, filter string, attrs []string, scope int) ([]ADObject, error) {
	return c.inner.Query(baseDN, filter, attrs, scope)
}

// QueryBatched is like Query but invokes callback per batch, allowing
// the caller to pace between pages.
func (c *Client) QueryBatched(
	baseDN, filter string,
	attrs []string,
	scope, batchSize int,
	callback func([]ADObject) error,
) error {
	ch := make(chan []ADObject, 4)
	errCh := make(chan error, 1)

	go func() {
		errCh <- c.inner.QueryWithBatchChannel(baseDN, filter, attrs, scope, batchSize, ch)
	}()

	for batch := range ch {
		if err := callback(batch); err != nil {
			return err
		}
	}

	return <-errCh
}

// GetDomain returns high-level domain metadata via MS-ADCAP.
func (c *Client) GetDomain() (*sopa.ADCAPActiveDirectoryDomain, error) {
	return c.inner.ADCAPGetADDomain()
}

// GetForest returns forest metadata via MS-ADCAP.
func (c *Client) GetForest() (*sopa.ADCAPActiveDirectoryForest, error) {
	return c.inner.ADCAPGetADForest()
}
