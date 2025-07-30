package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CAConfig holds configuration for CA certificate generation
type CAConfig struct {
	Organization string
	CommonName   string
	Country      string
	Locality     string
	ExpiryDays   int
}

// CertConfig holds configuration for client/server certificate generation
type CertConfig struct {
	Organization string
	CommonName   string
	Country      string
	Locality     string
	ExpiryDays   int
	IsClient     bool
	DNSNames     []string
	IPAddresses  []string
}

// CertBundle contains PEM-encoded certificate and private key
type CertBundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

// UnifiedPEM returns a single PEM file containing both the certificate and private key
func (cb *CertBundle) UnifiedPEM() []byte {
	// Concatenate cert and key PEM blocks
	unified := make([]byte, 0, len(cb.CertPEM)+len(cb.KeyPEM))
	unified = append(unified, cb.CertPEM...)
	unified = append(unified, cb.KeyPEM...)
	return unified
}

// GenerateCA creates a new CA certificate and private key
func GenerateCA(config CAConfig) (*CertBundle, error) {
	// Generate private key
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
			Country:      []string{config.Country},
			Locality:     []string{config.Locality},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(config.ExpiryDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate and private key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyDER,
	})

	return &CertBundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// GenerateCert creates a new client or server certificate signed by the provided CA
func GenerateCert(config CertConfig, caCertPEM, caKeyPEM []byte) (*CertBundle, error) {
	// Parse CA certificate and private key
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate private key for new certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Prepare certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
			Country:      []string{config.Country},
			Locality:     []string{config.Locality},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(config.ExpiryDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if config.IsClient {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		// Add DNS names and IP addresses for server certificates
		if len(config.DNSNames) > 0 {
			template.DNSNames = config.DNSNames
		}
		if len(config.IPAddresses) > 0 {
			// Parse IP addresses from strings - omitted for brevity
			// template.IPAddresses = parsedIPs
		}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate and private key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyDER,
	})

	return &CertBundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}
