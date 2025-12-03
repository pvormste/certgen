package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pvormste/certgen/internal/certificate"
)

// NewServer creates and configures a new MCP server with certificate generation tools.
func NewServer() *server.MCPServer {
	s := server.NewMCPServer("Certgen", "1.0.0",
		server.WithToolCapabilities(true),
	)

	// Register tools
	s.AddTool(generateCATool(), handleGenerateCA)
	s.AddTool(generateServerCertTool(), handleGenerateServerCert)
	s.AddTool(generateClientCertTool(), handleGenerateClientCert)

	return s
}

// generateCATool defines the generate_ca tool schema.
func generateCATool() mcp.Tool {
	return mcp.NewTool("generate_ca",
		mcp.WithDescription("Generate a self-signed Certificate Authority (CA) certificate and private key"),
		mcp.WithString("organization",
			mcp.Required(),
			mcp.Description("Organization name for the CA certificate"),
		),
		mcp.WithString("commonName",
			mcp.Required(),
			mcp.Description("Common Name (CN) for the CA certificate"),
		),
		mcp.WithString("country",
			mcp.Required(),
			mcp.Description("Country code (e.g., US, DE, UK)"),
		),
		mcp.WithString("locality",
			mcp.Required(),
			mcp.Description("City or locality name"),
		),
		mcp.WithNumber("expiryDays",
			mcp.Required(),
			mcp.Description("Number of days the certificate is valid"),
		),
	)
}

// generateServerCertTool defines the generate_server_certificate tool schema.
func generateServerCertTool() mcp.Tool {
	return mcp.NewTool("generate_server_certificate",
		mcp.WithDescription("Generate a server certificate signed by the provided CA"),
		mcp.WithString("caCert",
			mcp.Required(),
			mcp.Description("PEM encoded CA certificate"),
		),
		mcp.WithString("caKey",
			mcp.Required(),
			mcp.Description("PEM encoded CA private key"),
		),
		mcp.WithString("organization",
			mcp.Required(),
			mcp.Description("Organization name for the server certificate"),
		),
		mcp.WithString("commonName",
			mcp.Required(),
			mcp.Description("Common Name (CN) for the server certificate"),
		),
		mcp.WithString("country",
			mcp.Required(),
			mcp.Description("Country code (e.g., US, DE, UK)"),
		),
		mcp.WithString("locality",
			mcp.Required(),
			mcp.Description("City or locality name"),
		),
		mcp.WithNumber("expiryDays",
			mcp.Required(),
			mcp.Description("Number of days the certificate is valid"),
		),
		mcp.WithString("dnsNames",
			mcp.Description("Comma-separated list of DNS names (e.g., localhost,example.com)"),
		),
		mcp.WithString("ipAddresses",
			mcp.Description("Comma-separated list of IP addresses (e.g., 127.0.0.1,192.168.1.1)"),
		),
	)
}

// generateClientCertTool defines the generate_client_certificate tool schema.
func generateClientCertTool() mcp.Tool {
	return mcp.NewTool("generate_client_certificate",
		mcp.WithDescription("Generate a client certificate signed by the provided CA"),
		mcp.WithString("caCert",
			mcp.Required(),
			mcp.Description("PEM encoded CA certificate"),
		),
		mcp.WithString("caKey",
			mcp.Required(),
			mcp.Description("PEM encoded CA private key"),
		),
		mcp.WithString("organization",
			mcp.Required(),
			mcp.Description("Organization name for the client certificate"),
		),
		mcp.WithString("commonName",
			mcp.Required(),
			mcp.Description("Common Name (CN) for the client certificate"),
		),
		mcp.WithString("country",
			mcp.Required(),
			mcp.Description("Country code (e.g., US, DE, UK)"),
		),
		mcp.WithString("locality",
			mcp.Required(),
			mcp.Description("City or locality name"),
		),
		mcp.WithNumber("expiryDays",
			mcp.Required(),
			mcp.Description("Number of days the certificate is valid"),
		),
	)
}

// handleGenerateCA handles the generate_ca tool call.
func handleGenerateCA(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	org := req.GetString("organization", "")
	cn := req.GetString("commonName", "")
	country := req.GetString("country", "")
	locality := req.GetString("locality", "")
	expiryDays := req.GetInt("expiryDays", 365)

	config := certificate.CAConfig{
		Organization: org,
		CommonName:   cn,
		Country:      country,
		Locality:     locality,
		ExpiryDays:   expiryDays,
	}

	bundle, err := certificate.GenerateCA(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	output := fmt.Sprintf(`## CA Certificate

`+"```"+`
%s`+"```"+`

## Private Key

`+"```"+`
%s`+"```", string(bundle.CertPEM), string(bundle.KeyPEM))

	return mcp.NewToolResultText(output), nil
}

// handleGenerateServerCert handles the generate_server_certificate tool call.
func handleGenerateServerCert(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caCert := req.GetString("caCert", "")
	caKey := req.GetString("caKey", "")
	org := req.GetString("organization", "")
	cn := req.GetString("commonName", "")
	country := req.GetString("country", "")
	locality := req.GetString("locality", "")
	expiryDays := req.GetInt("expiryDays", 365)
	dnsNamesStr := req.GetString("dnsNames", "")
	ipAddressesStr := req.GetString("ipAddresses", "")

	var dnsNames []string
	if dnsNamesStr != "" {
		dnsNames = strings.Split(dnsNamesStr, ",")
		for i := range dnsNames {
			dnsNames[i] = strings.TrimSpace(dnsNames[i])
		}
	}

	var ipAddresses []string
	if ipAddressesStr != "" {
		ipAddresses = strings.Split(ipAddressesStr, ",")
		for i := range ipAddresses {
			ipAddresses[i] = strings.TrimSpace(ipAddresses[i])
		}
	}

	config := certificate.CertConfig{
		Organization: org,
		CommonName:   cn,
		Country:      country,
		Locality:     locality,
		ExpiryDays:   expiryDays,
		IsClient:     false,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	bundle, err := certificate.GenerateCert(config, []byte(caCert), []byte(caKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	output := fmt.Sprintf(`## Server Certificate

`+"```"+`
%s`+"```"+`

## Private Key

`+"```"+`
%s`+"```"+`

## Unified PEM (Certificate + Key)

`+"```"+`
%s`+"```"+`

## Certificate Chain (Server Cert + CA Cert)

`+"```"+`
%s`+"```"+`

## Full Chain (Server Cert + CA Cert + Key)

`+"```"+`
%s`+"```",
		string(bundle.CertPEM),
		string(bundle.KeyPEM),
		string(bundle.UnifiedPEM()),
		string(bundle.ChainPEM([]byte(caCert))),
		string(bundle.FullChainPEM([]byte(caCert))))

	return mcp.NewToolResultText(output), nil
}

// handleGenerateClientCert handles the generate_client_certificate tool call.
func handleGenerateClientCert(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	caCert := req.GetString("caCert", "")
	caKey := req.GetString("caKey", "")
	org := req.GetString("organization", "")
	cn := req.GetString("commonName", "")
	country := req.GetString("country", "")
	locality := req.GetString("locality", "")
	expiryDays := req.GetInt("expiryDays", 365)

	config := certificate.CertConfig{
		Organization: org,
		CommonName:   cn,
		Country:      country,
		Locality:     locality,
		ExpiryDays:   expiryDays,
		IsClient:     true,
	}

	bundle, err := certificate.GenerateCert(config, []byte(caCert), []byte(caKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %w", err)
	}

	output := fmt.Sprintf(`## Client Certificate

`+"```"+`
%s`+"```"+`

## Private Key

`+"```"+`
%s`+"```"+`

## Unified PEM (Certificate + Key)

`+"```"+`
%s`+"```"+`

## Certificate Chain (Client Cert + CA Cert)

`+"```"+`
%s`+"```"+`

## Full Chain (Client Cert + CA Cert + Key)

`+"```"+`
%s`+"```",
		string(bundle.CertPEM),
		string(bundle.KeyPEM),
		string(bundle.UnifiedPEM()),
		string(bundle.ChainPEM([]byte(caCert))),
		string(bundle.FullChainPEM([]byte(caCert))))

	return mcp.NewToolResultText(output), nil
}

