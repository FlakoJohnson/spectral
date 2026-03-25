// Package transport - PKINIT support using RedTeamPentesting/adauth's pkinit package.
//
// Performs a PKINIT AS exchange (RFC 4556) to obtain a Kerberos TGT from an RSA
// certificate, writes it to a temporary CCache file, and hands it off to the NNS
// layer via the existing CredentialCCache path.
package transport

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/ccachetools"
	"github.com/RedTeamPentesting/adauth/pkinit"
	v8config "github.com/jcmturner/gokrb5/v8/config"
)

// PKINITAuthenticate performs a PKINIT AS exchange against kdcHost:88,
// returning the TGT as a temporary ccache file path. The caller must delete the file.
// opts controls name resolution and TCP/UDP transport used to reach the KDC.
func PKINITAuthenticate(ctx context.Context, username, domain, kdcHost string, cert *x509.Certificate, key *rsa.PrivateKey, opts ResolverOptions) (tempCCachePath string, err error) {
	if username == "" {
		return "", fmt.Errorf("PKINIT: username is required")
	}
	if domain == "" {
		return "", fmt.Errorf("PKINIT: domain is required")
	}
	if kdcHost == "" {
		return "", fmt.Errorf("PKINIT: KDC host is required")
	}

	realm := strings.ToUpper(domain)
	kdcAddr := net.JoinHostPort(kdcHost, "88")

	cfg, err := v8config.NewFromString(fmt.Sprintf("[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n  udp_preference_limit = 1\n  allow_weak_crypto = true\n[realms]\n  %s = {\n    kdc = %s\n    admin_server = %s\n  }\n", realm, realm, kdcAddr, kdcHost))
	if err != nil {
		return "", fmt.Errorf("PKINIT: build KRB5 config: %w", err)
	}

	ccache, err := pkinit.Authenticate(ctx, username, realm, cert, key, cfg,
		pkinit.WithDialer(&net.Dialer{Resolver: buildResolver(opts)}),
	)
	if err != nil {
		return "", fmt.Errorf("PKINIT: AS exchange: %w", err)
	}

	ccacheBytes, err := ccachetools.MarshalCCache(ccache)
	if err != nil {
		return "", fmt.Errorf("PKINIT: marshal CCache: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "sopa-pkinit-*.ccache")
	if err != nil {
		return "", fmt.Errorf("PKINIT: create temp ccache: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(ccacheBytes); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("PKINIT: write temp ccache: %w", err)
	}

	return tmpFile.Name(), nil
}

// LoadPFX decodes a PKCS#12 (.pfx/.p12) file and returns the RSA private key
// and certificate. It delegates to adauth.DecodePFX which correctly handles
// the Microsoft-specific cert/chain ordering quirk in pkcs12.DecodeChain.
func LoadPFX(pfxFile, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	data, err := os.ReadFile(pfxFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read PFX file: %w", err)
	}

	key, cert, _, err := adauth.DecodePFX(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decode PFX: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("PFX key is %T, PKINIT requires RSA", key)
	}

	return rsaKey, cert, nil
}

// LoadPEM loads an RSA private key and certificate from separate PEM files.
func LoadPEM(certFile, keyFile string) (*rsa.PrivateKey, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in cert file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in key file")
	}

	var rsaKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		rsaKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse PKCS1 RSA key: %w", err)
		}
	case "PRIVATE KEY":
		pk, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse PKCS8 key: %w", parseErr)
		}
		var ok bool
		rsaKey, ok = pk.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("key is %T, PKINIT requires RSA", pk)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported PEM key type: %s", keyBlock.Type)
	}

	return rsaKey, cert, nil
}
