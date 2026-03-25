// Package transport implements the NNS (.NET NegotiateStream) and NMF (.NET Message
// Framing) protocol layers used by Active Directory Web Services (ADWS) on port 9389.
//
// Protocol stack (bottom to top):
//
//	TCP Socket (net.tcp://dc:9389)
//	NNS - .NET NegotiateStream (SPNEGO/NTLM/Kerberos authentication + message protection)
//	NMF - .NET Message Framing (record boundaries + binary XML encoding negotiation)
//	SOAP/XML (application layer)
package transport

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	"github.com/oiweiwei/go-msrpc/ssp/ntlm"
	"github.com/oiweiwei/go-msrpc/ssp/spnego"
	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
	krbcredentials "github.com/oiweiwei/gokrb5.fork/v9/credentials"
)

// ProtectionLevel defines the message protection requested during NNS negotiation.
// It controls whether GSS-API wraps messages with signing only or with encryption.
type ProtectionLevel int

const (
	// ProtectionNone - No message protection requested (still performs the normal NNS/SPNEGO handshake).
	ProtectionNone ProtectionLevel = iota
	// ProtectionSign - Message integrity (uses SPNEGO, can negotiate Kerberos or NTLM)
	ProtectionSign
	// ProtectionEncryptAndSign - Message confidentiality and integrity (uses SPNEGO)
	ProtectionEncryptAndSign
)

// CredentialType defines the type of credential provided for authentication.
type CredentialType int

const (
	// Password-based authentication
	CredentialPassword CredentialType = iota
	// NTLM hash authentication (hex-encoded MD4 of password)
	CredentialNTHash
	// Kerberos credential cache (ccache file path or from KRB5CCNAME env)
	CredentialCCache
	// Anonymous authentication (empty credentials)
	CredentialAnonymous
	// PKINIT certificate-based Kerberos pre-authentication (RFC 4556)
	CredentialClientCert
	// Kerberos AES session key (hex-encoded AES-128 or AES-256 key)
	CredentialAESKey
)

// NNSConnection represents a .NET NegotiateStream connection with SPNEGO/NTLM/Kerberos
// authentication and message signing/sealing capabilities.
//
// References:
//   - [MS-NNS]: .NET NegotiateStream Protocol
//   - Uses go-msrpc/ssp for GSS-API authentication (SPNEGO, NTLM, Kerberos)
type NNSConnection struct {
	conn net.Conn

	// Authentication settings
	domain          string
	username        string
	useKerberos     bool   // If true, use SPNEGO (Kerberos preferred); if false, use NTLM
	targetSPN       string // Service Principal Name for the target (e.g., "host/dc.example.com")
	protectionLevel ProtectionLevel

	// Credential information
	credentialType CredentialType
	password       string            // For CredentialPassword
	ntHash         string            // For CredentialNTHash (hex-encoded)
	aesKey         string            // For CredentialAESKey (hex-encoded AES-128 or AES-256)
	ccachePath     string            // For CredentialCCache (optional, uses KRB5CCNAME if empty)
	cert           *x509.Certificate // For CredentialClientCert
	key            *rsa.PrivateKey   // For CredentialClientCert

	ctx context.Context

	// DNS/dial options used for KDC connections.
	resolverOpts ResolverOptions

	// Authentication state
	authenticated bool
}

// WithResolverOptions sets the ResolverOptions used for all KDC TCP connections
// made by this NNSConnection (Kerberos AS/TGS exchanges and PKINIT). It returns
// the receiver so calls can be chained onto any New* constructor.
func (nns *NNSConnection) WithResolverOptions(opts ResolverOptions) *NNSConnection {
	nns.resolverOpts = opts
	return nns
}

// kdcDialer implements client.KDCDialer using a net.Dialer backed by a custom
// *net.Resolver so that KDC TCP connections honour ResolverOptions.
type kdcDialer struct {
	opts ResolverOptions
}

func (d kdcDialer) Dial(network, address string) (net.Conn, error) {
	if d.opts.DialContext != nil {
		return d.opts.DialContext(context.Background(), network, address)
	}
	dialer := &net.Dialer{Resolver: buildResolver(d.opts)}
	return dialer.DialContext(context.Background(), network, address)
}

// Ensure kdcDialer satisfies the interface at compile time.
var _ krbclient.KDCDialer = kdcDialer{}

// NewNNSConnection creates an NNS connection over an established TCP socket using
// password credentials. If targetSPN is empty, the SPN is derived as
// "host/<domain>" during the authentication handshake.
func NewNNSConnection(conn net.Conn, domain, username, password, targetSPN string, useKerberos bool, protectionLevel ProtectionLevel) *NNSConnection {
	return &NNSConnection{
		conn:            conn,
		domain:          domain,
		username:        username,
		password:        password,
		useKerberos:     useKerberos,
		targetSPN:       targetSPN,
		protectionLevel: protectionLevel,
		credentialType:  CredentialPassword,
		ctx:             context.Background(),
		authenticated:   false,
	}
}

// NewNNSConnectionWithNTHash creates a new NNS connection using NTLM hash authentication.
func NewNNSConnectionWithNTHash(conn net.Conn, domain, username, ntHash, targetSPN string, useKerberos bool, protectionLevel ProtectionLevel) *NNSConnection {
	return &NNSConnection{
		conn:            conn,
		domain:          domain,
		username:        username,
		ntHash:          ntHash,
		useKerberos:     useKerberos,
		targetSPN:       targetSPN,
		protectionLevel: protectionLevel,
		credentialType:  CredentialNTHash,
		ctx:             context.Background(),
		authenticated:   false,
	}
}

// NewNNSConnectionWithAESKey creates a new NNS connection using a Kerberos AES session key
// (overpass-the-hash with AES; works even when RC4-HMAC is disabled on the DC).
// aesKey must be a hex-encoded 16-byte (AES-128) or 32-byte (AES-256) key.
func NewNNSConnectionWithAESKey(conn net.Conn, domain, username, aesKey, targetSPN string, protectionLevel ProtectionLevel) *NNSConnection {
	return &NNSConnection{
		conn:            conn,
		domain:          domain,
		username:        username,
		aesKey:          aesKey,
		useKerberos:     true, // AES key always implies Kerberos
		targetSPN:       targetSPN,
		protectionLevel: protectionLevel,
		credentialType:  CredentialAESKey,
		ctx:             context.Background(),
		authenticated:   false,
	}
}

// NewNNSConnectionWithCCache creates a new NNS connection using Kerberos credential cache.
// ccachePath can be empty to use the KRB5CCNAME environment variable.
func NewNNSConnectionWithCCache(conn net.Conn, domain, username, ccachePath, targetSPN string, protectionLevel ProtectionLevel) *NNSConnection {
	return &NNSConnection{
		conn:            conn,
		domain:          domain,
		username:        username,
		ccachePath:      ccachePath,
		useKerberos:     true, // CCache requires Kerberos
		targetSPN:       targetSPN,
		protectionLevel: protectionLevel,
		credentialType:  CredentialCCache,
		ctx:             context.Background(),
		authenticated:   false,
	}
}

// NewNNSConnectionWithPKINIT creates a new NNS connection using PKINIT certificate-based
// Kerberos pre-authentication (RFC 4556 / MS-PKCA). The cert and key must be RSA.
func NewNNSConnectionWithPKINIT(conn net.Conn, domain, username string, cert *x509.Certificate, key *rsa.PrivateKey, targetSPN string, protectionLevel ProtectionLevel) *NNSConnection {
	return &NNSConnection{
		conn:            conn,
		domain:          domain,
		username:        username,
		cert:            cert,
		key:             key,
		useKerberos:     true, // PKINIT always results in a Kerberos credential
		targetSPN:       targetSPN,
		protectionLevel: protectionLevel,
		credentialType:  CredentialClientCert,
		ctx:             context.Background(),
		authenticated:   false,
	}
}

// NewNNSConnectionAnonymous creates a new NNS connection using anonymous authentication.
func NewNNSConnectionAnonymous(conn net.Conn, targetSPN string, useKerberos bool, protectionLevel ProtectionLevel) *NNSConnection {
	return &NNSConnection{
		conn:            conn,
		useKerberos:     useKerberos,
		targetSPN:       targetSPN,
		protectionLevel: protectionLevel,
		credentialType:  CredentialAnonymous,
		ctx:             context.Background(),
		authenticated:   false,
	}
}

// Authenticate performs authentication handshake over NNS protocol using GSS-API.
//
// Authentication Logic:
//   - Always use SPNEGO
//   - If useKerberos = false: SPNEGO with NTLM-only
//   - If useKerberos = true: SPNEGO with Kerberos-only
//
// Flow:
//  1. Initialize GSS-API security context with credentials and mechanisms
//  2. Client → Server: InitSecContext() → HandshakeInProgress
//  3. Server → Client: AcceptSecContext() → HandshakeInProgress or HandshakeDone
//  4. [Optional] Client → Server: Continue until HandshakeDone
//
// Returns error if authentication fails.
func (nns *NNSConnection) Authenticate() error {
	if nns.authenticated {
		return nil
	}
	nns.debugf("authenticate start mode=%s cred=%d targetSPN=%q user=%q", nns.authModeLabel(), nns.credentialType, nns.targetSPN, nns.username)

	mechType := ssp.MechanismTypeSPNEGO
	nns.debugf("mechanism selected oid=%s", mechType.String())

	// Build GSSAPI context options.
	var contextOpts []gssapi.ContextOption

	// Build credential based on credential type
	fullUsername := nns.fullUsername()

	var creds interface{}
	switch nns.credentialType {
	case CredentialPassword:
		if nns.password == "" {
			return fmt.Errorf("password required but not provided")
		}
		creds = credential.NewFromPassword(fullUsername, nns.password)
		nns.debugf("credential=password principal=%q", fullUsername)

	case CredentialNTHash:
		if nns.ntHash == "" {
			return fmt.Errorf("NT hash required but not provided")
		}
		// For Kerberos, NTHash can be used as RC4-HMAC key (etype 23).
		// Note: fails if the DC has RC4-HMAC disabled. Use --aes-key instead.
		// For NTLM, use it directly.
		creds = credential.NewFromNTHash(fullUsername, nns.ntHash)
		nns.debugf("credential=nthash principal=%q", fullUsername)

	case CredentialAESKey:
		if nns.aesKey == "" {
			return fmt.Errorf("AES key required but not provided")
		}
		// Detect etype from hex string length: 32 hex chars = 16B (AES-128, etype 17),
		// 64 hex chars = 32B (AES-256, etype 18).
		const etypeAES128 = 17
		const etypeAES256 = 18
		var keyType int
		switch len(nns.aesKey) {
		case 32:
			keyType = etypeAES128
		case 64:
			keyType = etypeAES256
		default:
			return fmt.Errorf("--aes-key must be 32 hex chars (AES-128) or 64 hex chars (AES-256), got %d", len(nns.aesKey))
		}
		creds = credential.NewFromEncryptionKey(fullUsername, keyType, nns.aesKey)
		nns.debugf("credential=aeskey etype=%d principal=%q", keyType, fullUsername)

	case CredentialCCache:
		if !nns.useKerberos {
			return fmt.Errorf("ccache credentials require Kerberos (useKerberos=true)")
		}
		ccachePath, err := nns.resolveCCachePath()
		if err != nil {
			return err
		}
		nns.debugf("credential=ccache principal=%q path=%q", fullUsername, ccachePath)

		ccache, err := loadCCache(ccachePath)
		if err != nil {
			return fmt.Errorf("failed to load ccache from %s: %w", ccachePath, err)
		}

		creds = credential.NewFromCCacheV9(fullUsername, ccache)

	case CredentialClientCert:
		if nns.cert == nil || nns.key == nil {
			return fmt.Errorf("ClientCert credentials require a certificate and RSA key")
		}
		nns.debugf("credential=clientcert principal=%q kdc=%q", fullUsername, nns.targetHost())

		ccachePath, err := PKINITAuthenticate(nns.ctx, nns.username, nns.domain, nns.targetHost(), nns.cert, nns.key, nns.resolverOpts)
		if err != nil {
			return fmt.Errorf("PKINIT AS exchange failed: %w", err)
		}
		defer os.Remove(ccachePath) //nolint:errcheck

		ccache, err := loadCCache(ccachePath)
		if err != nil {
			return fmt.Errorf("load PKINIT ccache: %w", err)
		}

		creds = credential.NewFromCCacheV9(fullUsername, ccache)

	case CredentialAnonymous:
		// Anonymous authentication
		creds = credential.Anonymous()
		nns.debugf("credential=anonymous")

	default:
		return fmt.Errorf("unknown credential type: %d", nns.credentialType)
	}

	// Add credential to context
	contextOpts = append(contextOpts, gssapi.WithCredential(creds))

	// Build SPNEGO with exactly one enabled mechanism.
	var mechFactory gssapi.MechanismFactory
	if nns.useKerberos {
		krbCfg := nns.buildKRB5Config()
		nns.debugf("kerberos config targetHost=%q defaultRealm=%q", nns.targetHost(), nns.krbDefaultRealm(krbCfg))
		krbFactory := gssapi.WithDefaultConfig(ssp.KRB5, krbCfg)

		spnegoCfg := &spnego.Config{
			MechanismsList: []gssapi.MechanismFactory{krbFactory},
		}

		mechFactory = gssapi.WithDefaultConfig(ssp.SPNEGO, spnegoCfg)

		// Make sub-mechanism configs discoverable from local context (used by SPNEGO internals).
		contextOpts = append(contextOpts, krbFactory)
	} else {
		ntlmConfig := ntlm.NewConfig()
		switch nns.protectionLevel {
		case ProtectionEncryptAndSign:
			ntlmConfig.Confidentiality = true
			ntlmConfig.Integrity = true
		case ProtectionSign:
			ntlmConfig.Confidentiality = false
			ntlmConfig.Integrity = true
		case ProtectionNone:
			ntlmConfig.Confidentiality = false
			ntlmConfig.Integrity = false
		}

		ntlmFactory := gssapi.WithDefaultConfig(ssp.NTLM, ntlmConfig)
		spnegoCfg := &spnego.Config{
			MechanismsList: []gssapi.MechanismFactory{ntlmFactory},
		}

		mechFactory = gssapi.WithDefaultConfig(ssp.SPNEGO, spnegoCfg)

		// Make sub-mechanism configs discoverable from local context (used by SPNEGO internals).
		contextOpts = append(contextOpts, ntlmFactory)
	}

	contextOpts = append(contextOpts, mechFactory)

	// Create security context with proper ContextOptions
	nns.ctx = gssapi.NewSecurityContext(nns.ctx, contextOpts...)
	nns.debugf("security context initialized")

	// Build GSS init options (these are required to initialize context capabilities/state)
	var initOpts []gssapi.Option
	initOpts = append(initOpts, gssapi.WithMechanismType(mechType))
	if nns.targetSPN != "" {
		initOpts = append(initOpts, gssapi.WithTargetName(nns.targetSPN))
	}

	// Request protection capabilities according to configured protection level.
	var requestedCaps gssapi.Cap
	switch nns.protectionLevel {
	case ProtectionEncryptAndSign:
		requestedCaps = gssapi.Confidentiality | gssapi.Integrity
	case ProtectionSign:
		requestedCaps = gssapi.Integrity
	case ProtectionNone:
		requestedCaps = 0
	}

	if nns.useKerberos {
		requestedCaps |= gssapi.MutualAuthn
	}

	if nns.useKerberos && strings.TrimSpace(os.Getenv("ADWS_KRB5_NO_INTEG")) == "1" {
		requestedCaps &^= gssapi.Integrity
		nns.debugf("kerberos integrity disabled (ADWS_KRB5_NO_INTEG=1)")
	}
	if nns.useKerberos && strings.TrimSpace(os.Getenv("ADWS_KRB5_SIGN_ONLY")) == "1" {
		requestedCaps = gssapi.Integrity
		nns.debugf("kerberos sign-only mode enabled")
	}
	if requestedCaps != 0 {
		initOpts = append(initOpts, gssapi.WithRequest(requestedCaps))
	}

	// Start authentication handshake.
	token, err := gssapi.InitSecurityContext(nns.ctx, &gssapi.Token{}, initOpts...)
	if err != nil && err != gssapi.ContextContinueNeeded(nns.ctx) {
		nns.debugf("init security context failed: %v", err)
		return fmt.Errorf("failed to initialize security context: %w", err)
	}
	nns.debugf("init security context tokenLen=%d state=%v", payloadLen(token), err)

	firstMsgID := MessageIDInProgress
	if err == nil && gssapi.IsComplete(nns.ctx) {
		firstMsgID = MessageIDDone
	}

	firstPayload := []byte{}
	if token != nil {
		firstPayload = token.Payload
	}

	if err := nns.sendHandshake(firstMsgID, firstPayload); err != nil {
		return fmt.Errorf("failed to send initial handshake: %w", err)
	}
	nns.debugf("sent handshake msg=%s payload=%d", handshakeMessageName(firstMsgID), len(firstPayload))

	if firstMsgID == MessageIDDone {
		// WaitingForHandshakeDone: peer must answer with terminal handshake frame.
		msgID, serverPayload, err := nns.recvHandshake()
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return fmt.Errorf("GSS token exchange timeout - server not responding")
			}
			return err
		}
		nns.debugf("recv handshake msg=%s payload=%d", handshakeMessageName(msgID), len(serverPayload))

		switch msgID {
		case MessageIDDone:
			nns.authenticated = true
			nns.debugf("authentication complete (first-call complete)")
			return nil
		case MessageIDError:
			if len(serverPayload) >= 4 {
				errCode := binary.LittleEndian.Uint32(serverPayload)
				return fmt.Errorf("server returned handshake error: 0x%08x", errCode)
			}
			return fmt.Errorf("server returned handshake error")
		default:
			return fmt.Errorf("invalid completion handshake message type: 0x%02x", msgID)
		}
	}

	// Step 7: Exchange tokens until complete
	for {
		// Use existing recvHandshake function which handles the proper frame format
		msgID, serverPayload, err := nns.recvHandshake()
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				return fmt.Errorf("GSS token exchange timeout - server not responding")
			}
			return err
		}
		nns.debugf("recv handshake msg=%s payload=%d", handshakeMessageName(msgID), len(serverPayload))

		// Handle different message types per MS-NNS.
		switch msgID {
		case MessageIDInProgress: // 0x16
		case MessageIDDone: // 0x14
		case MessageIDError: // 0x15
			if len(serverPayload) >= 4 {
				errCode := binary.LittleEndian.Uint32(serverPayload)
				return fmt.Errorf("server returned handshake error: 0x%08x", errCode)
			}
			return fmt.Errorf("server returned handshake error")
		default:
			return fmt.Errorf("unknown handshake message type: 0x%02x", msgID)
		}

		// Process GSS token through mechanism
		token, err = gssapi.InitSecurityContext(nns.ctx, &gssapi.Token{Payload: serverPayload}, initOpts...)
		nns.debugf("continue init context tokenLen=%d state=%v", payloadLen(token), err)

		if err == nil && gssapi.IsComplete(nns.ctx) {
			// Send final mechanism token as HandshakeDone.
			if msgID != MessageIDDone && token != nil && len(token.Payload) > 0 {
				if err := nns.sendHandshake(MessageIDDone, token.Payload); err != nil {
					return fmt.Errorf("failed to send final handshake done token: %w", err)
				}
			} else if msgID != MessageIDDone {
				if err := nns.sendHandshake(MessageIDDone, []byte{}); err != nil {
					return fmt.Errorf("failed to send final handshake done: %w", err)
				}
			}

			if msgID == MessageIDDone {
				nns.authenticated = true
				nns.debugf("authentication complete (server done terminal)")
				return nil
			}

			// Wait for peer completion frame (WaitingForHandshakeDone -> Authenticated).
			msgID2, serverPayload2, err2 := nns.recvHandshake()
			if err2 != nil {
				return fmt.Errorf("failed to receive completion handshake frame: %w", err2)
			}

			switch msgID2 {
			case MessageIDDone:
				// Interop note: some SSP stacks require consuming non-empty terminal payloads
				// to finalize security context state before first wrapped data frame.
				if len(serverPayload2) > 0 && !nns.useKerberos {
					token2, err3 := gssapi.InitSecurityContext(nns.ctx, &gssapi.Token{Payload: serverPayload2}, initOpts...)
					if err3 != nil && err3 != gssapi.ContextComplete(nns.ctx) && err3 != gssapi.ContextContinueNeeded(nns.ctx) {
						return fmt.Errorf("failed to process completion handshake payload: %w", err3)
					}
					if token2 != nil && len(token2.Payload) > 0 {
						if err := nns.sendHandshake(MessageIDDone, token2.Payload); err != nil {
							return fmt.Errorf("failed to send completion handshake response token: %w", err)
						}
					}
				}
			case MessageIDError:
				if len(serverPayload2) >= 8 {
					errCode := binary.LittleEndian.Uint32(serverPayload2[4:8])
					return fmt.Errorf("server returned completion handshake error: 0x%08x", errCode)
				}
				return fmt.Errorf("server returned completion handshake error")
			default:
				return fmt.Errorf("invalid completion handshake message type: 0x%02x", msgID2)
			}

			nns.authenticated = true
			nns.debugf("authentication complete")

			return nil
		} else if err != nil && err != gssapi.ContextContinueNeeded(nns.ctx) {
			return fmt.Errorf("GSS authentication error: %w", err)
		}

		// Send continuation handshake if needed.
		if token != nil && len(token.Payload) > 0 {
			if err := nns.sendHandshake(MessageIDInProgress, token.Payload); err != nil {
				return fmt.Errorf("failed to send continuation token: %w", err)
			}
		}
	}
}

// loadCCache loads a Kerberos credential cache file from disk.
func loadCCache(path string) (*krbcredentials.CCache, error) {
	ccache, err := krbcredentials.LoadCCache(path)
	if err != nil {
		return nil, err
	}
	return ccache, nil
}

func (nns *NNSConnection) debugf(format string, args ...any) {
	if os.Getenv("ADWS_DEBUG_NNS") != "1" {
		return
	}
	fmt.Printf("[adws-debug][nns] "+format+"\n", args...)
}

func (nns *NNSConnection) authModeLabel() string {
	if nns.useKerberos {
		return "spnego"
	}
	return "ntlm"
}

func (nns *NNSConnection) krbDefaultRealm(cfg *krb5.Config) string {
	if cfg == nil || cfg.GetKRB5Config() == nil {
		return ""
	}
	return cfg.GetKRB5Config().LibDefaults.DefaultRealm
}

func payloadLen(tok *gssapi.Token) int {
	if tok == nil {
		return 0
	}
	return len(tok.Payload)
}

func handshakeMessageName(id byte) string {
	switch id {
	case MessageIDInProgress:
		return "InProgress"
	case MessageIDDone:
		return "Done"
	case MessageIDError:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", id)
	}
}

func (nns *NNSConnection) requestedCaps() gssapi.Cap {
	switch nns.protectionLevel {
	case ProtectionEncryptAndSign:
		return gssapi.Confidentiality | gssapi.Integrity
	case ProtectionSign:
		return gssapi.Integrity
	default:
		return 0
	}
}

func (nns *NNSConnection) wrapCaps() gssapi.Cap {
	requested := nns.requestedCaps()
	negotiated := gssapi.FromContext(nns.ctx).Capabilities
	if negotiated == 0 {
		return requested
	}

	effective := requested & negotiated
	if effective != 0 {
		return effective
	}

	if requested.IsSet(gssapi.Integrity) && negotiated.IsSet(gssapi.Integrity) {
		return gssapi.Integrity
	}

	return requested
}

func (nns *NNSConnection) fullUsername() string {
	username := strings.TrimSpace(nns.username)
	if username == "" {
		return username
	}

	if strings.Contains(username, "\\") || strings.Contains(username, "/") || strings.Contains(username, "@") {
		return username
	}

	domain := strings.TrimSpace(nns.domain)
	if domain == "" {
		return username
	}

	if nns.useKerberos {
		domain = strings.ToUpper(domain)
	}

	return domain + "\\" + username
}

func (nns *NNSConnection) resolveCCachePath() (string, error) {
	path := strings.TrimSpace(nns.ccachePath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("KRB5CCNAME"))
	}
	if path == "" {
		return "", fmt.Errorf("ccache credentials require CCachePath or KRB5CCNAME environment variable")
	}

	if strings.HasPrefix(strings.ToUpper(path), "FILE:") {
		path = path[5:]
	}

	return path, nil
}

func (nns *NNSConnection) buildKRB5Config() *krb5.Config {
	krbCfg := krb5.NewConfig()

	realm := strings.ToUpper(strings.TrimSpace(nns.domain))
	if realm == "" {
		if username := strings.TrimSpace(nns.username); strings.Contains(username, "@") {
			parts := strings.SplitN(username, "@", 2)
			if len(parts) == 2 {
				realm = strings.ToUpper(strings.TrimSpace(parts[1]))
			}
		}
	}

	host := strings.TrimSpace(nns.targetHost())
	if host != "" && realm != "" {
		cfg := krbconfig.New()
		cfg.LibDefaults.DefaultRealm = realm
		cfg.LibDefaults.DNSLookupKDC = false
		cfg.LibDefaults.DNSLookupRealm = false
		cfg.LibDefaults.UDPPreferenceLimit = 1
		cfg.LibDefaults.AllowWeakCrypto = true

		cfg.Realms = []krbconfig.Realm{
			{
				Realm:         realm,
				DefaultDomain: realm,
				AdminServer:   []string{host},
				KDC:           []string{net.JoinHostPort(host, "88")},
				KPasswdServer: []string{net.JoinHostPort(host, "464")},
				MasterKDC:     []string{host},
			},
		}

		domain := strings.TrimSpace(nns.domain)
		if domain != "" {
			cfg.DomainRealm = map[string]string{
				"." + strings.ToLower(domain): realm,
				strings.ToLower(domain):       realm,
			}
		}

		krbCfg.KRB5Config = cfg
	}

	krbCfg.CCachePath = nns.ccachePath
	krbCfg.DisablePAFXFAST = true
	krbCfg.AnyServiceClassSPN = true
	krbCfg.DCEStyle = false
	krbCfg.KDCDialer = kdcDialer{opts: nns.resolverOpts}

	return krbCfg
}

func (nns *NNSConnection) targetHost() string {
	target := strings.TrimSpace(nns.targetSPN)
	if target == "" {
		return ""
	}

	if idx := strings.Index(target, "/"); idx >= 0 && idx < len(target)-1 {
		target = target[idx+1:]
	}

	if idx := strings.Index(target, ":"); idx >= 0 {
		target = target[:idx]
	}

	return strings.TrimSpace(target)
}

// Send sends data with optional signing and sealing using GSS-API Wrap.
//
// After authentication, NNS Data Messages have the format:
//
//	[0:4]   PayloadSize (uint32, little-endian) - size of wrapped payload
//	[4:.]   Payload (signed/encrypted data from GSS_Wrap)
//
// Uses GSS_Wrap from the negotiated security mechanism.
func (nns *NNSConnection) Send(data []byte) error {
	if !nns.authenticated {
		return fmt.Errorf("not authenticated")
	}
	nns.debugf("send appData len=%d", len(data))

	if nns.protectionLevel == ProtectionNone {
		// MS-NNS Data Message still uses a 4-byte little-endian length prefix.
		// MS-NNS 2.2.2: PayloadSize maximum is 0x0000FC30 (64,560).
		if len(data) > 0x0000FC30 {
			return fmt.Errorf("NNS data size exceeds protocol maximum: %d", len(data))
		}

		// No protection: send data directly with 4-byte size header.
		sizeBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sizeBytes, uint32(len(data)))
		if _, err := nns.conn.Write(sizeBytes); err != nil {
			return fmt.Errorf("failed to write NNS data size: %w", err)
		}

		if _, err := nns.conn.Write(data); err != nil {
			return fmt.Errorf("failed to write NNS data: %w", err)
		}
		return nil
	}

	// Use GSS-API Wrap for message protection with negotiated capabilities.
	caps := nns.wrapCaps()
	nns.debugf("send caps requested=%v negotiated=%v effective=%v", nns.requestedCaps(), gssapi.FromContext(nns.ctx).Capabilities, caps)

	wrappedMsg, err := gssapi.Wrap(nns.ctx, &gssapi.MessageToken{
		Payload:      data,
		Capabilities: caps,
	})
	if err != nil {
		return fmt.Errorf("failed to wrap message: %w", err)
	}

	// MS-NNS wire format (MS-NNS §2.2.2): [size(4 LE)][GSS_Wrap output]
	// go-msrpc returns Signature and Payload separately. Both NTLM
	// (NTLMSSP_MESSAGE_SIGNATURE(16) || encrypted_data) and Kerberos CFX
	// (RFC 4121 §4.2.4 token_header || ciphertext) place Signature first.
	wrappedData := make([]byte, 0, len(wrappedMsg.Signature)+len(wrappedMsg.Payload))
	wrappedData = append(wrappedData, wrappedMsg.Signature...)
	wrappedData = append(wrappedData, wrappedMsg.Payload...)

	// Write full frame in a single TCP write: [size(4 LE)][wrapped-data]
	frame := make([]byte, 4+len(wrappedData))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(wrappedData)))
	copy(frame[4:], wrappedData)
	if _, err := nns.conn.Write(frame); err != nil {
		return fmt.Errorf("failed to write NNS data: %w", err)
	}
	nns.debugf("send protected frame sigLen=%d payloadLen=%d totalLen=%d", len(wrappedMsg.Signature), len(wrappedMsg.Payload), len(frame))
	return nil
}

// Recv receives data with optional signature verification and unsealing using GSS-API Unwrap.
//
// After authentication, NNS Data Messages have the format:
//
//	[0:4]   PayloadSize (uint32, little-endian)
//	[4:.]   Payload (signed/encrypted data)
//
// Uses GSS_Unwrap from the negotiated security mechanism.
func (nns *NNSConnection) Recv(buf []byte) (int, error) {
	if !nns.authenticated {
		return 0, fmt.Errorf("not authenticated")
	}

	if nns.protectionLevel == ProtectionNone {
		// No protection: still framed as a Data Message: [size(4 LE)][payload].
		sizeBytes := make([]byte, 4)
		if _, err := io.ReadFull(nns.conn, sizeBytes); err != nil {
			return 0, fmt.Errorf("failed to read NNS data size: %w", err)
		}
		totalSize := binary.LittleEndian.Uint32(sizeBytes)
		if totalSize == 0 {
			return 0, fmt.Errorf("failed to receive NNS data frame")
		}
		if totalSize > 0x0000FC30 {
			return 0, fmt.Errorf("NNS data size exceeds protocol maximum: %d", totalSize)
		}
		if int(totalSize) > len(buf) {
			return 0, fmt.Errorf("unprotected message too large for buffer")
		}
		if _, err := io.ReadFull(nns.conn, buf[:totalSize]); err != nil {
			return 0, fmt.Errorf("failed to read NNS data (want %d): %w", totalSize, err)
		}
		return int(totalSize), nil
	}

	// In Authenticated state, incoming data MUST be parsed as Data Message:
	// first 4 bytes are PayloadSize (MS-NNS 2.2.2 / 3.1.5.5).
	sizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(nns.conn, sizeBytes); err != nil {
		return 0, fmt.Errorf("failed to read NNS data size: %w", err)
	}
	totalSize := binary.LittleEndian.Uint32(sizeBytes)

	if totalSize == 0 {
		return 0, fmt.Errorf("failed to receive protected NNS data frame")
	}
	nns.debugf("recv protected frame payloadLen=%d", totalSize)

	// MS-NNS 2.2.2: PayloadSize maximum is 0x0000FC30 (64,560).
	if totalSize > 0x0000FC30 {
		return 0, fmt.Errorf("NNS data size exceeds protocol maximum: %d", totalSize)
	}

	// Read combined signature + encrypted payload
	wrappedData := make([]byte, totalSize)
	if n, err := io.ReadFull(nns.conn, wrappedData); err != nil {
		return 0, fmt.Errorf("failed to read NNS data (got %d/%d): %w", n, totalSize, err)
	}

	caps := nns.wrapCaps()

	var (
		unwrappedMsg *gssapi.MessageToken
		err          error
	)

	if nns.useKerberos {
		// Kerberos CFX wrap token (RFC 4121 §4.2.4): 16-byte token header followed
		// by encrypted payload. go-msrpc expects the token header (plus RRC-rotated
		// bytes and the AES confounder) as Signature, and the remaining ciphertext
		// as Payload. TOK_ID 05 04 identifies a Wrap token (vs 05 05 for MIC).
		const hdrLen = 16
		if len(wrappedData) < hdrLen || wrappedData[0] != 0x05 || wrappedData[1] != 0x04 {
			return 0, fmt.Errorf("invalid Kerberos CFX wrap token (got %02x %02x)", wrappedData[0], wrappedData[1])
		}
		ec := int(binary.BigEndian.Uint16(wrappedData[4:6]))
		rrc := int(binary.BigEndian.Uint16(wrappedData[6:8]))
		nns.debugf("recv krb5 wrap token ec=%d rrc=%d", ec, rrc)
		// Signature boundary: token header (16) + EC padding (ec) +
		// RRC-rotated bytes (rrc) + AES confounder (16).
		sigLen := hdrLen + ec + rrc + hdrLen
		if sigLen <= hdrLen || sigLen > len(wrappedData) {
			return 0, fmt.Errorf("Kerberos wrap token signature boundary out of range (sigLen=%d, total=%d)", sigLen, len(wrappedData))
		}
		unwrappedMsg, err = gssapi.Unwrap(nns.ctx, &gssapi.MessageToken{
			Signature:    wrappedData[:sigLen],
			Payload:      wrappedData[sigLen:],
			Capabilities: caps,
		})
	} else {
		// NTLM: NTLMSSP_MESSAGE_SIGNATURE is always 16 bytes (MS-NLMP §2.2.2.9.1).
		const ntlmSigLen = 16
		if len(wrappedData) < ntlmSigLen {
			return 0, fmt.Errorf("NTLM wrapped data too short (%d bytes)", len(wrappedData))
		}
		unwrappedMsg, err = gssapi.Unwrap(nns.ctx, &gssapi.MessageToken{
			Signature:    wrappedData[:ntlmSigLen],
			Payload:      wrappedData[ntlmSigLen:],
			Capabilities: caps,
		})
	}
	if err != nil {
		nns.debugf("unwrap failed wrappedLen=%d err=%v", len(wrappedData), err)
		return 0, fmt.Errorf("failed to unwrap message: %w", err)
	}

	// Copy unwrapped data to buffer
	if len(unwrappedMsg.Payload) > len(buf) {
		return 0, fmt.Errorf("unwrapped message too large for buffer")
	}
	copy(buf, unwrappedMsg.Payload)
	nns.debugf("recv unwrapped payload len=%d", len(unwrappedMsg.Payload))
	return len(unwrappedMsg.Payload), nil
}

// sendHandshake sends an NNS handshake message during authentication.
//
// NNS Handshake Message Format (per MS-NNS 2.2.1):
//
//	[0]     MessageId (uint8)
//	        0x16 = HandshakeInProgress
//	        0x14 = HandshakeDone
//	        0x15 = HandshakeError
//	[1]     MajorVersion (uint8, must be 0x01)
//	[2]     MinorVersion (uint8, must be 0x00)
//	[3]     HighByteOfPayloadSize (high-order byte of size)
//	[4]     LowByteOfPayloadSize (low-order byte of size)
//	[5:.]   AuthPayload (SPNEGO or NTLM token bytes)
//
// Note: Payload size is encoded in BIG-ENDIAN (network byte order)
func (nns *NNSConnection) sendHandshake(messageID byte, payload []byte) error {
	payloadSize := uint16(len(payload))

	header := make([]byte, 5)
	header[0] = messageID
	header[1] = 1
	header[2] = 0
	header[3] = byte((payloadSize >> 8) & 0xFF)
	header[4] = byte(payloadSize & 0xFF)

	// Write header (5 bytes)
	if _, err := nns.conn.Write(header); err != nil {
		return fmt.Errorf("failed to write handshake header: %w", err)
	}

	// Write payload if present
	if len(payload) > 0 {
		if _, err := nns.conn.Write(payload); err != nil {
			return fmt.Errorf("failed to write handshake payload: %w", err)
		}
	}

	return nil
}

// recvHandshake receives an NNS handshake message during authentication.
//
// Returns:
//   - messageID: The message identifier (0x16=InProgress, 0x14=Done, 0x15=Error)
//   - payload: The authentication payload (SPNEGO or NTLM token)
//   - err: Any error encountered during receive
func (nns *NNSConnection) recvHandshake() (messageID byte, payload []byte, err error) {
	// Set read deadline to 5 seconds
	nns.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer nns.conn.SetReadDeadline(time.Time{})

	// Read 5-byte header
	header := make([]byte, 5)
	if _, err := io.ReadFull(nns.conn, header); err != nil {
		return 0, nil, fmt.Errorf("failed to read handshake header: %w", err)
	}

	// Parse header fields per MS-NNS 2.2.1
	messageID = header[0]
	majorVersion := header[1]
	minorVersion := header[2]
	// PayloadLength is uint16 big-endian (network byte order): [3]=HighByte, [4]=LowByte
	payloadLength := uint16(header[3])<<8 | uint16(header[4])

	// Validate version
	if majorVersion != 1 || minorVersion != 0 {
		return 0, nil, fmt.Errorf("unsupported NNS version: %d.%d (expected 1.0)", majorVersion, minorVersion)
	}

	// Read payload if present
	if payloadLength > 0 {
		// Sanity check: prevent excessive allocations
		if payloadLength > 65535 { // Max uint16
			return 0, nil, fmt.Errorf("handshake payload too large: %d bytes", payloadLength)
		}

		payload = make([]byte, payloadLength)
		if _, err := io.ReadFull(nns.conn, payload); err != nil {
			return 0, nil, fmt.Errorf("failed to read handshake payload: %w", err)
		}
	}

	return messageID, payload, nil
}

// MessageID constants for NNS handshake/data (per MS-NNS 2.2.1)
const (
	MessageIDInProgress byte = 0x16 // HandshakeInProgress: Continue negotiation
	MessageIDDone       byte = 0x14 // HandshakeDone: Authentication completed successfully
	MessageIDError      byte = 0x15 // HandshakeError: Authentication failed
)

// Close closes the underlying connection.
func (nns *NNSConnection) Close() error {
	if nns.conn != nil {
		return nns.conn.Close()
	}
	return nil
}

// IsAuthenticated returns whether the connection has completed authentication.
func (nns *NNSConnection) IsAuthenticated() bool {
	return nns.authenticated
}
