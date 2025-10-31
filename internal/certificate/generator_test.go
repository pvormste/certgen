package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	tests := []struct {
		name    string
		config  CAConfig
		wantErr bool
	}{
		{
			name: "valid CA config",
			config: CAConfig{
				Organization: "Test Org",
				CommonName:   "Test CA",
				Country:      "US",
				Locality:     "Test City",
				ExpiryDays:   365,
			},
			wantErr: false,
		},
		{
			name: "zero expiry days",
			config: CAConfig{
				Organization: "Test Org",
				CommonName:   "Test CA",
				Country:      "US",
				Locality:     "Test City",
				ExpiryDays:   0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCA(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify the certificate PEM block
				block, _ := pem.Decode(got.CertPEM)
				if block == nil {
					t.Error("Failed to decode certificate PEM")
					return
				}
				if block.Type != "CERTIFICATE" {
					t.Errorf("Expected PEM block type 'CERTIFICATE', got %s", block.Type)
				}

				// Parse the certificate
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("Failed to parse certificate: %v", err)
					return
				}

				// Verify certificate fields
				if !cert.IsCA {
					t.Error("Certificate is not a CA certificate")
				}
				if cert.Subject.Organization[0] != tt.config.Organization {
					t.Errorf("Expected Organization %s, got %s", tt.config.Organization, cert.Subject.Organization[0])
				}
				if cert.Subject.CommonName != tt.config.CommonName {
					t.Errorf("Expected CommonName %s, got %s", tt.config.CommonName, cert.Subject.CommonName)
				}

				// Verify the private key PEM block
				block, _ = pem.Decode(got.KeyPEM)
				if block == nil {
					t.Error("Failed to decode private key PEM")
					return
				}
				if block.Type != "EC PRIVATE KEY" {
					t.Errorf("Expected PEM block type 'EC PRIVATE KEY', got %s", block.Type)
				}
			}
		})
	}
}

func TestGenerateCert(t *testing.T) {
	// First generate a CA to sign the certificates
	caConfig := CAConfig{
		Organization: "Test CA Org",
		CommonName:   "Test CA",
		Country:      "US",
		Locality:     "Test City",
		ExpiryDays:   365,
	}
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	tests := []struct {
		name    string
		config  CertConfig
		wantErr bool
	}{
		{
			name: "valid client certificate",
			config: CertConfig{
				Organization: "Test Org",
				CommonName:   "Test Client",
				Country:      "US",
				Locality:     "Test City",
				ExpiryDays:   365,
				IsClient:     true,
			},
			wantErr: false,
		},
		{
			name: "valid server certificate",
			config: CertConfig{
				Organization: "Test Org",
				CommonName:   "Test Server",
				Country:      "US",
				Locality:     "Test City",
				ExpiryDays:   365,
				IsClient:     false,
				DNSNames:     []string{"localhost", "example.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCert(tt.config, ca.CertPEM, ca.KeyPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Verify the certificate PEM block
				block, _ := pem.Decode(got.CertPEM)
				if block == nil {
					t.Error("Failed to decode certificate PEM")
					return
				}
				if block.Type != "CERTIFICATE" {
					t.Errorf("Expected PEM block type 'CERTIFICATE', got %s", block.Type)
				}

				// Parse the certificate
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Errorf("Failed to parse certificate: %v", err)
					return
				}

				// Verify certificate fields
				if cert.IsCA {
					t.Error("Certificate should not be a CA certificate")
				}
				if cert.Subject.Organization[0] != tt.config.Organization {
					t.Errorf("Expected Organization %s, got %s", tt.config.Organization, cert.Subject.Organization[0])
				}
				if cert.Subject.CommonName != tt.config.CommonName {
					t.Errorf("Expected CommonName %s, got %s", tt.config.CommonName, cert.Subject.CommonName)
				}

				// Verify expiry
				expectedExpiry := time.Now().Add(time.Duration(tt.config.ExpiryDays) * 24 * time.Hour)
				if cert.NotAfter.Sub(expectedExpiry).Abs() > time.Minute {
					t.Errorf("Certificate expiry time differs by more than 1 minute from expected")
				}

				// Verify the private key PEM block
				block, _ = pem.Decode(got.KeyPEM)
				if block == nil {
					t.Error("Failed to decode private key PEM")
					return
				}
				if block.Type != "EC PRIVATE KEY" {
					t.Errorf("Expected PEM block type 'EC PRIVATE KEY', got %s", block.Type)
				}

				// Verify certificate usage
				if tt.config.IsClient {
					found := false
					for _, usage := range cert.ExtKeyUsage {
						if usage == x509.ExtKeyUsageClientAuth {
							found = true
							break
						}
					}
					if !found {
						t.Error("Client certificate missing ExtKeyUsageClientAuth")
					}
				} else {
					found := false
					for _, usage := range cert.ExtKeyUsage {
						if usage == x509.ExtKeyUsageServerAuth {
							found = true
							break
						}
					}
					if !found {
						t.Error("Server certificate missing ExtKeyUsageServerAuth")
					}

					// Verify DNS names for server certificates
					if len(tt.config.DNSNames) > 0 {
						if len(cert.DNSNames) != len(tt.config.DNSNames) {
							t.Errorf("Expected %d DNS names, got %d", len(tt.config.DNSNames), len(cert.DNSNames))
						}
						for i, name := range tt.config.DNSNames {
							if cert.DNSNames[i] != name {
								t.Errorf("Expected DNS name %s, got %s", name, cert.DNSNames[i])
							}
						}
					}
				}
			}
		})
	}
}

func TestGenerateCertInvalidCA(t *testing.T) {
	config := CertConfig{
		Organization: "Test Org",
		CommonName:   "Test Client",
		Country:      "US",
		Locality:     "Test City",
		ExpiryDays:   365,
		IsClient:     true,
	}

	// Test with invalid CA PEM data
	_, err := GenerateCert(config, []byte("invalid"), []byte("invalid"))
	if err == nil {
		t.Error("GenerateCert() should fail with invalid CA PEM data")
	}
}

func TestChainPEM(t *testing.T) {
	// Generate a CA
	caConfig := CAConfig{
		Organization: "Test CA Org",
		CommonName:   "Test CA",
		Country:      "US",
		Locality:     "Test City",
		ExpiryDays:   365,
	}
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate a client certificate
	certConfig := CertConfig{
		Organization: "Test Org",
		CommonName:   "Test Client",
		Country:      "US",
		Locality:     "Test City",
		ExpiryDays:   365,
		IsClient:     true,
	}
	bundle, err := GenerateCert(certConfig, ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Test ChainPEM
	chain := bundle.ChainPEM(ca.CertPEM)
	if len(chain) == 0 {
		t.Error("ChainPEM returned empty data")
	}

	// Verify the chain contains both certificates
	// Count the number of certificate blocks
	remainingData := chain
	certCount := 0
	for len(remainingData) > 0 {
		block, rest := pem.Decode(remainingData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certCount++
			// Verify we can parse the certificate
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("Failed to parse certificate %d in chain: %v", certCount, err)
			}
		}
		remainingData = rest
	}

	if certCount != 2 {
		t.Errorf("Expected 2 certificates in chain, got %d", certCount)
	}

	// Verify the first certificate is the leaf (not a CA)
	firstBlock, _ := pem.Decode(chain)
	if firstBlock == nil {
		t.Fatal("Failed to decode first certificate in chain")
	}
	firstCert, err := x509.ParseCertificate(firstBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse first certificate: %v", err)
	}
	if firstCert.IsCA {
		t.Error("First certificate in chain should be leaf (non-CA), but it's a CA")
	}
}

func TestFullChainPEM(t *testing.T) {
	// Generate a CA
	caConfig := CAConfig{
		Organization: "Test CA Org",
		CommonName:   "Test CA",
		Country:      "US",
		Locality:     "Test City",
		ExpiryDays:   365,
	}
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate a server certificate
	certConfig := CertConfig{
		Organization: "Test Org",
		CommonName:   "Test Server",
		Country:      "US",
		Locality:     "Test City",
		ExpiryDays:   365,
		IsClient:     false,
		DNSNames:     []string{"localhost"},
	}
	bundle, err := GenerateCert(certConfig, ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Test FullChainPEM
	fullChain := bundle.FullChainPEM(ca.CertPEM)
	if len(fullChain) == 0 {
		t.Error("FullChainPEM returned empty data")
	}

	// Verify the chain contains two certificates and one private key
	remainingData := fullChain
	certCount := 0
	keyCount := 0
	for len(remainingData) > 0 {
		block, rest := pem.Decode(remainingData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certCount++
			// Verify we can parse the certificate
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("Failed to parse certificate %d in full chain: %v", certCount, err)
			}
		} else if block.Type == "EC PRIVATE KEY" {
			keyCount++
			// Verify we can parse the private key
			_, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				t.Errorf("Failed to parse private key in full chain: %v", err)
			}
		}
		remainingData = rest
	}

	if certCount != 2 {
		t.Errorf("Expected 2 certificates in full chain, got %d", certCount)
	}
	if keyCount != 1 {
		t.Errorf("Expected 1 private key in full chain, got %d", keyCount)
	}

	// Verify the first certificate is the leaf (not a CA)
	firstBlock, _ := pem.Decode(fullChain)
	if firstBlock == nil {
		t.Fatal("Failed to decode first certificate in full chain")
	}
	firstCert, err := x509.ParseCertificate(firstBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse first certificate: %v", err)
	}
	if firstCert.IsCA {
		t.Error("First certificate in full chain should be leaf (non-CA), but it's a CA")
	}
}
