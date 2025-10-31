package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"

	"github.com/pvormste/certgen/assets"
	"github.com/pvormste/certgen/internal/certificate"
)

// FormData holds the form data for certificate generation
type FormData struct {
	Organization string   `json:"organization"`
	CommonName   string   `json:"commonName"`
	Country      string   `json:"country"`
	Locality     string   `json:"locality"`
	ExpiryDays   int      `json:"expiryDays"`
	IsClient     bool     `json:"isClient"`
	DNSNames     []string `json:"dnsNames,omitempty"`
	IPAddresses  []string `json:"ipAddresses,omitempty"`
}

// Server represents the HTTP server for the certificate generator
type Server struct {
	templates *template.Template
}

// NewServer creates a new Server instance
func NewServer() (*Server, error) {
	// Parse templates from embedded file system
	tmpl, err := template.ParseFS(assets.TemplateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	return &Server{
		templates: tmpl,
	}, nil
}

// Start starts the HTTP server
func (s *Server) Start(addr string) error {
	// Create a sub-filesystem for static files
	staticRoot, err := fs.Sub(assets.StaticFS, "static")
	if err != nil {
		return err
	}

	// Static file server using embedded files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot))))

	// Route handlers
	http.HandleFunc("/", s.handleIndex)
	http.HandleFunc("/generate/ca", s.handleGenerateCA)
	http.HandleFunc("/generate/cert", s.handleGenerateCert)

	log.Printf("Server starting on %s", addr)
	return http.ListenAndServe(addr, nil)
}

// handleIndex renders the main page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := s.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// handleGenerateCA handles CA certificate generation
func (s *Server) handleGenerateCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var formData FormData
	if err := json.NewDecoder(r.Body).Decode(&formData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	config := certificate.CAConfig{
		Organization: formData.Organization,
		CommonName:   formData.CommonName,
		Country:      formData.Country,
		Locality:     formData.Locality,
		ExpiryDays:   formData.ExpiryDays,
	}

	bundle, err := certificate.GenerateCA(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create ZIP file
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Add certificate to ZIP
	certWriter, err := zipWriter.Create("ca.crt")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := certWriter.Write(bundle.CertPEM); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add private key to ZIP
	keyWriter, err := zipWriter.Create("ca.key")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := keyWriter.Write(bundle.KeyPEM); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add unified PEM to ZIP
	unifiedWriter, err := zipWriter.Create("ca.pem")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := unifiedWriter.Write(bundle.UnifiedPEM()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := zipWriter.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=ca-certificate.zip")
	if _, err := io.Copy(w, buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// handleGenerateCert handles client/server certificate generation
func (s *Server) handleGenerateCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get CA files
	caCertFile, _, err := r.FormFile("caCert")
	if err != nil {
		http.Error(w, "CA certificate file required", http.StatusBadRequest)
		return
	}
	defer caCertFile.Close()

	caKeyFile, _, err := r.FormFile("caKey")
	if err != nil {
		http.Error(w, "CA private key file required", http.StatusBadRequest)
		return
	}
	defer caKeyFile.Close()

	// Read CA files
	caCertPEM, err := io.ReadAll(caCertFile)
	if err != nil {
		http.Error(w, "Failed to read CA certificate", http.StatusInternalServerError)
		return
	}

	caKeyPEM, err := io.ReadAll(caKeyFile)
	if err != nil {
		http.Error(w, "Failed to read CA private key", http.StatusInternalServerError)
		return
	}

	// Parse form data
	var formData FormData
	formDataStr := r.FormValue("formData")
	if err := json.Unmarshal([]byte(formDataStr), &formData); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Generate certificate
	config := certificate.CertConfig{
		Organization: formData.Organization,
		CommonName:   formData.CommonName,
		Country:      formData.Country,
		Locality:     formData.Locality,
		ExpiryDays:   formData.ExpiryDays,
		IsClient:     formData.IsClient,
		DNSNames:     formData.DNSNames,
		IPAddresses:  formData.IPAddresses,
	}

	bundle, err := certificate.GenerateCert(config, caCertPEM, caKeyPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create ZIP file
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Determine file prefix based on certificate type
	prefix := "server"
	if formData.IsClient {
		prefix = "client"
	}

	// Add certificate to ZIP
	certWriter, err := zipWriter.Create(prefix + ".crt")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := certWriter.Write(bundle.CertPEM); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add private key to ZIP
	keyWriter, err := zipWriter.Create(prefix + ".key")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := keyWriter.Write(bundle.KeyPEM); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add unified PEM to ZIP
	unifiedWriter, err := zipWriter.Create(prefix + ".pem")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := unifiedWriter.Write(bundle.UnifiedPEM()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add certificate chain (cert + CA) to ZIP
	chainWriter, err := zipWriter.Create(prefix + "-chain.pem")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := chainWriter.Write(bundle.ChainPEM(caCertPEM)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add full chain (cert + CA + key) to ZIP
	fullChainWriter, err := zipWriter.Create(prefix + "-fullchain.pem")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := fullChainWriter.Write(bundle.FullChainPEM(caCertPEM)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := zipWriter.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+prefix+"-certificate.zip")
	if _, err := io.Copy(w, buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
