package random

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// OrgData represents organization data with country and locality
type OrgData struct {
	Suffix   string
	Country  string
	Locality string
}

// Predefined organization combinations
var organizations = []OrgData{
	{Suffix: "Ltd.", Country: "UK", Locality: "London"},
	{Suffix: "GmbH", Country: "DE", Locality: "Berlin"},
	{Suffix: "Inc.", Country: "US", Locality: "New York"},
	{Suffix: "S.A.", Country: "FR", Locality: "Paris"},
	{Suffix: "B.V.", Country: "NL", Locality: "Amsterdam"},
}

// RandomCAData represents random CA certificate data
type RandomCAData struct {
	Organization string `json:"organization"`
	CommonName   string `json:"commonName"`
	Country      string `json:"country"`
	Locality     string `json:"locality"`
	ExpiryDays   int    `json:"expiryDays"`
}

// RandomServerData represents random server certificate data
type RandomServerData struct {
	Organization string   `json:"organization"`
	CommonName   string   `json:"commonName"`
	Country      string   `json:"country"`
	Locality     string   `json:"locality"`
	ExpiryDays   int      `json:"expiryDays"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
}

// RandomClientData represents random client certificate data
type RandomClientData struct {
	Organization string `json:"organization"`
	CommonName   string `json:"commonName"`
	Country      string `json:"country"`
	Locality     string `json:"locality"`
	ExpiryDays   int    `json:"expiryDays"`
}

// GenerateRandomCA generates random CA certificate data
func GenerateRandomCA() RandomCAData {
	org := organizations[rand.Intn(len(organizations))]

	return RandomCAData{
		Organization: "Acme CA " + org.Suffix,
		CommonName:   "Acme CA",
		Country:      org.Country,
		Locality:     org.Locality,
		ExpiryDays:   365,
	}
}

// GenerateRandomServer generates random server certificate data
func GenerateRandomServer() RandomServerData {
	org := organizations[rand.Intn(len(organizations))]

	return RandomServerData{
		Organization: "Acme Server " + org.Suffix,
		CommonName:   "Acme Server",
		Country:      org.Country,
		Locality:     org.Locality,
		ExpiryDays:   365,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []string{"127.0.0.1"},
	}
}

// GenerateRandomClient generates random client certificate data
func GenerateRandomClient() RandomClientData {
	org := organizations[rand.Intn(len(organizations))]

	return RandomClientData{
		Organization: "Acme Client " + org.Suffix,
		CommonName:   "Acme Client",
		Country:      org.Country,
		Locality:     org.Locality,
		ExpiryDays:   365,
	}
}
