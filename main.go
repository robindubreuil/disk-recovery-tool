package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/* locales/*
var embedFS embed.FS

// BlockDevice represents a storage device
type BlockDevice struct {
	Name        string `json:"name"`
	Size        string `json:"size"`
	Type        string `json:"type"`
	Mountpoint  string `json:"mountpoint"`
	Description string `json:"description"`
}

// DumpOptions contains dump options
type DumpOptions struct {
	Device      string `json:"device"`
	Compression string `json:"compression"` // "xz" or "zstd"
}

// DumpResult contains the result of a dump
type DumpResult struct {
	Filename string    `json:"filename"`
	Checksum string    `json:"checksum"`
	Size     int64     `json:"size"`
	Duration string    `json:"duration"`
	Started  time.Time `json:"started"`
}

// Translations contains translations for a language
type Translations map[string]string

// I18n manages internationalization
type I18n struct {
	translations map[string]Translations
	defaultLang  string
}

// Session manages user sessions
type Session struct {
	ID        string
	CreatedAt time.Time
	LastUsed  time.Time
}

// DiskRecoveryServer manages the web server
type DiskRecoveryServer struct {
	tmpl             *template.Template
	activeDumps      sync.Map
	requireAuth      bool
	passwordHash     string
	plainPassword    string
	sessions         map[string]*Session
	sessionsMutex    sync.RWMutex
	i18n             *I18n
	checksums        map[string]*DumpResult
	checksumsMutex   sync.RWMutex
	useHTTPS         bool
	certFile         string
	keyFile          string
}

func NewDiskRecoveryServer(requireAuth bool, password, passwordHash string, useHTTPS bool, certFile, keyFile string) (*DiskRecoveryServer, error) {
	// Initialize i18n
	i18n, err := NewI18n()
	if err != nil {
		return nil, fmt.Errorf("error initializing i18n: %v", err)
	}

	// Create template functions with i18n
	funcMap := template.FuncMap{
		"t": func(key string, lang string) string {
			return i18n.Get(key, lang)
		},
		"version": func() string {
			return Version
		},
		"appName": func() string {
			return AppName
		},
		"appCopyright": func() string {
			return AppCopyright
		},
		"formatBytes": func(bytes int64) string {
			const unit = 1024
			if bytes < unit {
				return fmt.Sprintf("%d B", bytes)
			}
			div, exp := int64(unit), 0
			for n := bytes / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(embedFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %v", err)
	}
	
	server := &DiskRecoveryServer{
		tmpl:        tmpl,
		requireAuth: requireAuth,
		sessions:    make(map[string]*Session),
		checksums:   make(map[string]*DumpResult),
		i18n:        i18n,
		useHTTPS:    useHTTPS,
		certFile:    certFile,
		keyFile:     keyFile,
	}

	if requireAuth {
		if passwordHash != "" {
			server.passwordHash = passwordHash
		} else if password != "" {
			server.plainPassword = password
		} else {
			return nil, fmt.Errorf("password or hash required for authentication")
		}
	}

	return server, nil
}

// NewI18n initializes the internationalization system
func NewI18n() (*I18n, error) {
	i18n := &I18n{
		translations: make(map[string]Translations),
		defaultLang:  "en",
	}

	// Load translations
	languages := []string{"en", "fr"}
	for _, lang := range languages {
		content, err := embedFS.ReadFile(fmt.Sprintf("locales/%s.json", lang))
		if err != nil {
			return nil, fmt.Errorf("error reading locale %s: %v", lang, err)
		}

		var translations Translations
		if err := json.Unmarshal(content, &translations); err != nil {
			return nil, fmt.Errorf("error parsing locale %s: %v", lang, err)
		}

		i18n.translations[lang] = translations
	}

	return i18n, nil
}

// Get returns a translation
func (i *I18n) Get(key, lang string) string {
	if lang == "" {
		lang = i.defaultLang
	}

	if translations, exists := i.translations[lang]; exists {
		if value, exists := translations[key]; exists {
			return value
		}
	}

	// Fallback to default language
	if lang != i.defaultLang {
		if translations, exists := i.translations[i.defaultLang]; exists {
			if value, exists := translations[key]; exists {
				return value
			}
		}
	}

	// Fallback to key itself
	return key
}

// DetectLanguage detects the client's preferred language
func (i *I18n) DetectLanguage(r *http.Request) string {
	// Check language cookie
	if cookie, err := r.Cookie("lang"); err == nil {
		if _, exists := i.translations[cookie.Value]; exists {
			return cookie.Value
		}
	}

	// Parse Accept-Language header with proper priority handling
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang != "" {
		// Parse quality values
		type langQuality struct {
			lang string
			q    float64
		}
		
		var langs []langQuality
		parts := strings.Split(acceptLang, ",")
		
		for _, part := range parts {
			part = strings.TrimSpace(part)
			langParts := strings.Split(part, ";")
			lang := strings.TrimSpace(langParts[0])
			
			q := 1.0
			if len(langParts) > 1 {
				for _, param := range langParts[1:] {
					param = strings.TrimSpace(param)
					if strings.HasPrefix(param, "q=") {
						if val, err := strconv.ParseFloat(param[2:], 64); err == nil {
							q = val
						}
					}
				}
			}
			
			// Extract language code
			if len(lang) >= 2 {
				shortLang := strings.ToLower(lang[:2])
				langs = append(langs, langQuality{shortLang, q})
			}
		}
		
		// Sort by quality (highest first)
		var bestLang string
		bestQ := 0.0
		for _, lq := range langs {
			if _, exists := i.translations[lq.lang]; exists && lq.q > bestQ {
				bestLang = lq.lang
				bestQ = lq.q
			}
		}
		
		if bestLang != "" {
			return bestLang
		}
	}

	return i.defaultLang
}

// Auth middleware
func (s *DiskRecoveryServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth {
			next(w, r)
			return
		}

		// Check session
		if s.isAuthenticated(r) {
			next(w, r)
			return
		}

		// Redirect to login
		if r.URL.Path != "/login" && r.URL.Path != "/auth" && r.URL.Path != "/set-lang" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next(w, r)
	}
}

// isAuthenticated checks if the user is authenticated
func (s *DiskRecoveryServer) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}

	s.sessionsMutex.RLock()
	session, exists := s.sessions[cookie.Value]
	s.sessionsMutex.RUnlock()

	if !exists {
		return false
	}

	// Check expiration (24h)
	if time.Since(session.LastUsed) > 24*time.Hour {
		s.sessionsMutex.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMutex.Unlock()
		return false
	}

	// Update last used
	session.LastUsed = time.Now()
	return true
}

// generateSessionID generates a secure session ID
func (s *DiskRecoveryServer) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// loginHandler displays the login page
func (s *DiskRecoveryServer) loginHandler(w http.ResponseWriter, r *http.Request) {
	lang := s.i18n.DetectLanguage(r)
	
	data := struct {
		Lang      string
		Languages map[string]string
	}{
		Lang: lang,
		Languages: map[string]string{
			"en": "English",
			"fr": "Français",
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
	}
}

// authHandler handles authentication
func (s *DiskRecoveryServer) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}

	// Verify password
	valid := false
	if s.passwordHash != "" {
		// Verify hash (bcrypt or crypt)
		valid = s.verifyPasswordHash(password, s.passwordHash)
	} else {
		// Plain text comparison (constant time)
		valid = subtle.ConstantTimeCompare([]byte(password), []byte(s.plainPassword)) == 1
	}

	if !valid {
		time.Sleep(2 * time.Second) // Brute force protection
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID := s.generateSessionID()
	session := &Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	s.sessionsMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionsMutex.Unlock()

	// Session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.useHTTPS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   24 * 3600, // 24h
	})

	log.Printf("Authentication successful for session %s", sessionID[:8])
	http.Redirect(w, r, "/", http.StatusFound)
}

// verifyPasswordHash verifies a password hash
func (s *DiskRecoveryServer) verifyPasswordHash(password, hash string) bool {
	// Try bcrypt first
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err == nil {
		return true
	}

	// Fallback to Unix crypt() (format $6$ = SHA-512)
	if strings.HasPrefix(hash, "$") {
		cmd := exec.Command("openssl", "passwd", "-6", "-salt", 
			strings.Split(hash, "$")[2], password)
		output, err := cmd.Output()
		if err == nil {
			generatedHash := strings.TrimSpace(string(output))
			return subtle.ConstantTimeCompare([]byte(hash), []byte(generatedHash)) == 1
		}
	}

	return false
}

// setLangHandler changes the language
func (s *DiskRecoveryServer) setLangHandler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = "en"
	}

	// Verify language exists
	if _, exists := s.i18n.translations[lang]; !exists {
		lang = "en"
	}

	// Language cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "lang",
		Value:  lang,
		Path:   "/",
		MaxAge: 365 * 24 * 3600, // 1 year
		Secure: s.useHTTPS,
	})

	// Redirect to referrer or home
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/"
	}
	http.Redirect(w, r, referer, http.StatusFound)
}

// logoutHandler logs out the user
func (s *DiskRecoveryServer) logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.sessionsMutex.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMutex.Unlock()
	}

	// Expire cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
		Secure: s.useHTTPS,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

// getBlockDevices lists available block devices
func (s *DiskRecoveryServer) getBlockDevices() ([]BlockDevice, error) {
	cmd := exec.Command("lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lsblk error: %v", err)
	}

	var result struct {
		BlockDevices []BlockDevice `json:"blockdevices"`
	}
	
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("error parsing lsblk: %v", err)
	}

	// Filter to keep only whole disks (not partitions)
	var disks []BlockDevice
	for _, dev := range result.BlockDevices {
		if dev.Type == "disk" {
			// Add clearer description
			dev.Description = fmt.Sprintf("%s (%s)", dev.Name, dev.Size)
			disks = append(disks, dev)
		}
	}

	return disks, nil
}

// validateDevice verifies that a device is valid and safe
func (s *DiskRecoveryServer) validateDevice(device string) error {
	// Strict device name validation
	matched, err := regexp.MatchString(`^[a-zA-Z0-9]+$`, device)
	if err != nil || !matched {
		return fmt.Errorf("invalid device name: %s", device)
	}

	// Check that device exists and is a block device
	devicePath := "/dev/" + device
	info, err := os.Stat(devicePath)
	if err != nil {
		return fmt.Errorf("device not found: %s", devicePath)
	}

	// Verify it's a block device
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("not a block device: %s", devicePath)
	}

	return nil
}

// checkDependencies verifies required tools are available
func (s *DiskRecoveryServer) checkDependencies() error {
	required := []string{"dd", "lsblk", "sha256sum"}
	optional := map[string]string{
		"xz":   "XZ compression",
		"zstd": "ZSTD compression",
	}

	// Check required dependencies
	for _, cmd := range required {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command not found: %s", cmd)
		}
	}

	// Log optional dependencies
	for cmd, desc := range optional {
		if _, err := exec.LookPath(cmd); err != nil {
			log.Printf("Warning: %s not available (%s)", cmd, desc)
		}
	}

	return nil
}

// homeHandler displays the main page
func (s *DiskRecoveryServer) homeHandler(w http.ResponseWriter, r *http.Request) {
	devices, err := s.getBlockDevices()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error listing devices: %v", err), http.StatusInternalServerError)
		return
	}

	lang := s.i18n.DetectLanguage(r)

	// Check tool availability
	hasXz := s.hasCommand("xz")
	hasZstd := s.hasCommand("zstd")

	data := struct {
		Devices   []BlockDevice
		HasXz       bool
		HasZstd     bool
		Lang        string
		Languages   map[string]string
		UseHTTPS    bool
		RequireAuth bool
	}{
		Devices:   devices,
		HasXz:     hasXz,
		HasZstd:   hasZstd,
		Lang:      lang,
		Languages: map[string]string{
			"en": "English",
			"fr": "Français",
		},
		UseHTTPS:    s.useHTTPS,
		RequireAuth: s.requireAuth,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
	}
}

// hasCommand checks if a command is available
func (s *DiskRecoveryServer) hasCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// checksumsHandler displays the checksums page
func (s *DiskRecoveryServer) checksumsHandler(w http.ResponseWriter, r *http.Request) {
	lang := s.i18n.DetectLanguage(r)

	s.checksumsMutex.RLock()
	checksums := make([]*DumpResult, 0, len(s.checksums))
	for _, result := range s.checksums {
		checksums = append(checksums, result)
	}
	s.checksumsMutex.RUnlock()

	// Sort by date (newest first)
	for i := 0; i < len(checksums); i++ {
		for j := i + 1; j < len(checksums); j++ {
			if checksums[i].Started.Before(checksums[j].Started) {
				checksums[i], checksums[j] = checksums[j], checksums[i]
			}
		}
	}

	data := struct {
		Checksums []*DumpResult
		Lang      string
		Languages map[string]string
	}{
		Checksums: checksums,
		Lang:      lang,
		Languages: map[string]string{
			"en": "English",
			"fr": "Français",
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "checksums.html", data); err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
	}
}

// dumpHandler handles disk dumping and streaming
func (s *DiskRecoveryServer) dumpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse options
	options := DumpOptions{
		Device:      r.FormValue("device"),
		Compression: r.FormValue("compression"),
	}

	// Validation
	if options.Device == "" {
		http.Error(w, "Device required", http.StatusBadRequest)
		return
	}

	if err := s.validateDevice(options.Device); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !s.hasCommand(options.Compression) {
		http.Error(w, fmt.Sprintf("Compression tool not available: %s", options.Compression), http.StatusBadRequest)
		return
	}

	devicePath := "/dev/" + options.Device
	
	log.Printf("Starting dump of %s (compression: %s)", devicePath, options.Compression)

	timestamp := time.Now().Format("20060102_150405")
	extension := fmt.Sprintf(".img.%s", options.Compression)
	filename := fmt.Sprintf("disk_%s_%s%s", options.Device, timestamp, extension)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Cache-Control", "no-cache")

	result, err := s.streamDiskDump(w, devicePath, options, filename)
	if err != nil {
		log.Printf("Error dumping %s: %v", devicePath, err)
		return
	}

	// Store checksum
	s.checksumsMutex.Lock()
	s.checksums[result.Checksum] = result
	s.checksumsMutex.Unlock()

	log.Printf("Dump completed for %s - Checksum: %s", devicePath, result.Checksum)
}

// streamDiskDump executes the complete pipeline and streams to HTTP response
func (s *DiskRecoveryServer) streamDiskDump(w http.ResponseWriter, devicePath string, options DumpOptions, filename string) (*DumpResult, error) {
	startTime := time.Now()

	// dd command to read disk
	ddCmd := exec.Command("dd", "if="+devicePath, "bs=1M", "status=none")
	
	// Compression command
	var compCmd *exec.Cmd
	switch options.Compression {
	case "xz":
		compCmd = exec.Command("xz")
	case "zstd":
		compCmd = exec.Command("zstd")
	default:
		return nil, fmt.Errorf("unsupported compression: %s", options.Compression)
	}

	// Basic pipeline: dd → compression
	ddToComp, ddWriter := io.Pipe()
	ddCmd.Stdout = ddWriter
	ddCmd.Stderr = os.Stderr

	compCmd.Stdin = ddToComp
	compCmd.Stderr = os.Stderr

	finalReader, _ := compCmd.StdoutPipe()

	// Calculate checksum in parallel with TeeReader
	checksumReader, checksumWriter := io.Pipe()
	teeReader := io.TeeReader(finalReader, checksumWriter)
	
	hasher := sha256.New()
	checksumDone := make(chan string, 1)
	
	go func() {
		defer checksumReader.Close()
		io.Copy(hasher, checksumReader)
		checksum := hex.EncodeToString(hasher.Sum(nil))
		checksumDone <- checksum
	}()

	// Copy to HTTP response
	var bytesWritten int64
	copyDone := make(chan error, 1)
	go func() {
		defer checksumWriter.Close()
		n, err := io.Copy(w, teeReader)
		bytesWritten = n
		copyDone <- err
	}()

	// Start commands in order
	if err := ddCmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting dd: %v", err)
	}
	
	if err := compCmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting compression: %v", err)
	}

	// Handle pipe closing in order
	go func() {
		ddCmd.Wait()
		ddWriter.Close()
	}()

	go func() {
		compCmd.Wait()
	}()

	// Wait for copy completion
	if err := <-copyDone; err != nil {
		return nil, fmt.Errorf("HTTP copy error: %v", err)
	}

	// Get checksum
	checksum := <-checksumDone
	duration := time.Since(startTime)

	result := &DumpResult{
		Filename: filename,
		Checksum: checksum,
		Size:     bytesWritten,
		Duration: duration.String(),
		Started:  startTime,
	}

	// Log result with audit
	log.Printf("[AUDIT] Dump completed - File: %s, Size: %d bytes, Checksum: %s, Duration: %s",
		result.Filename, result.Size, result.Checksum, result.Duration)

	return result, nil
}

// restoreHandler handles image restoration to disk
func (s *DiskRecoveryServer) restoreHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (32MB max for headers)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	device := r.FormValue("restore_device")
	
	file, header, err := r.FormFile("image_file")
	if err != nil {
		http.Error(w, "File required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if device == "" {
		http.Error(w, "Destination device required", http.StatusBadRequest)
		return
	}

	if err := s.validateDevice(device); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	devicePath := "/dev/" + device
	filename := header.Filename

	log.Printf("[AUDIT] Starting restoration of %s to %s", filename, devicePath)

	// Detect file type
	isXz := strings.Contains(filename, ".xz")
	isZstd := strings.Contains(filename, ".zst")

	// Restoration pipeline
	if err := s.restoreFromStream(file, devicePath, isXz, isZstd); err != nil {
		log.Printf("[AUDIT] Restoration error %s → %s: %v", filename, devicePath, err)
		http.Error(w, fmt.Sprintf("Restoration error: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] Restoration completed: %s → %s", filename, devicePath)
	
	// JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Restoration completed on %s", devicePath),
	})
}

// restoreFromStream executes the restoration pipeline
func (s *DiskRecoveryServer) restoreFromStream(input io.Reader, devicePath string, isXz, isZstd bool) error {
	var currentReader io.Reader = input
	var commands []*exec.Cmd

	// Decompression step
	if isXz || isZstd {
		var decompCmd *exec.Cmd
		if isXz {
			decompCmd = exec.Command("xz", "-d", "-c")
		} else {
			decompCmd = exec.Command("zstd", "-d", "-c")
		}
		
		decompCmd.Stdin = currentReader
		decompCmd.Stderr = os.Stderr
		
		decompReader, err := decompCmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("decompression pipe error: %v", err)
		}
		
		if err := decompCmd.Start(); err != nil {
			return fmt.Errorf("decompression start error: %v", err)
		}
		
		currentReader = decompReader
		commands = append(commands, decompCmd)
	}

	// Write to disk with dd
	ddCmd := exec.Command("dd", "of="+devicePath, "bs=1M", "status=none")
	ddCmd.Stdin = currentReader
	ddCmd.Stderr = os.Stderr

	if err := ddCmd.Run(); err != nil {
		return fmt.Errorf("dd error: %v", err)
	}

	// Wait for all processes to finish
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("pipeline error: %v", err)
		}
	}

	return nil
}

// statusHandler provides server information
func (s *DiskRecoveryServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	versionInfo := GetVersionInfo()
	
	status := map[string]interface{}{
		"status":    "ready",
		"timestamp": time.Now().Unix(),
		"version":   versionInfo,
		"auth":      s.requireAuth,
		"https":     s.useHTTPS,
		"features": map[string]bool{
			"xz_compression":   s.hasCommand("xz"),
			"zstd_compression": s.hasCommand("zstd"),
			"checksum":        s.hasCommand("sha256sum"),
		},
	}
	
	json.NewEncoder(w).Encode(status)
}

func main() {
	// CLI arguments
	var (
		port         = flag.String("port", "8080", "Server listening port")
		password     = flag.String("password", "", "Plain text password for authentication")
		passwordHash = flag.String("password-hash", "", "Password hash (bcrypt or crypt)")
		useHTTPS     = flag.Bool("https", false, "Enable HTTPS")
		certFile     = flag.String("cert", "cert.pem", "TLS certificate file")
		keyFile      = flag.String("key", "key.pem", "TLS private key file")
		help         = flag.Bool("help", false, "Show help")
		version      = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *version {
		versionInfo := GetVersionInfo()
		fmt.Printf("%s v%s\n", versionInfo["name"], versionInfo["version"])
		fmt.Printf("Build: %s @ %s\n", versionInfo["git_commit"], versionInfo["build_time"])
		fmt.Printf("%s - %s\n", versionInfo["copyright"], versionInfo["license"])
		return
	}

	if *help {
		fmt.Printf("%s - Disk dump & restore over HTTP/HTTPS\n\n", GetVersionString())
		fmt.Printf("Usage: %s [options]\n\n", os.Args[0])
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
		fmt.Printf("\nExamples:\n")
		fmt.Printf("  # Server without authentication\n")
		fmt.Printf("  sudo %s\n\n", os.Args[0])
		fmt.Printf("  # With password\n")
		fmt.Printf("  sudo %s -password mypassword\n\n", os.Args[0])
		fmt.Printf("  # With HTTPS\n")
		fmt.Printf("  sudo %s -https -cert cert.pem -key key.pem\n\n", os.Args[0])
		fmt.Printf("  # With bcrypt hash\n")
		fmt.Printf("  sudo %s -password-hash '$2y$10$...'\n\n", os.Args[0])
		return
	}

	// Check root privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root to access block devices")
	}

	// Determine if authentication is required
	requireAuth := *password != "" || *passwordHash != ""

	// Check HTTPS configuration
	if *useHTTPS {
		if _, err := os.Stat(*certFile); os.IsNotExist(err) {
			log.Fatalf("Certificate file not found: %s", *certFile)
		}
		if _, err := os.Stat(*keyFile); os.IsNotExist(err) {
			log.Fatalf("Key file not found: %s", *keyFile)
		}
	}

	server, err := NewDiskRecoveryServer(requireAuth, *password, *passwordHash, *useHTTPS, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("Server creation error: %v", err)
	}

	// Check dependencies
	if err := server.checkDependencies(); err != nil {
		log.Fatalf("Missing dependencies: %v", err)
	}

	// Routes with authentication middleware
	http.HandleFunc("/login", server.loginHandler)
	http.HandleFunc("/auth", server.authHandler)
	http.HandleFunc("/logout", server.logoutHandler)
	http.HandleFunc("/set-lang", server.setLangHandler)
	http.HandleFunc("/", server.authMiddleware(server.homeHandler))
	http.HandleFunc("/dump", server.authMiddleware(server.dumpHandler))
	http.HandleFunc("/restore", server.authMiddleware(server.restoreHandler))
	http.HandleFunc("/checksums", server.authMiddleware(server.checksumsHandler))
	http.HandleFunc("/status", server.statusHandler)

	serverPort := ":" + *port
	protocol := "http"
	if *useHTTPS {
		protocol = "https"
	}

	log.Printf("%s started on %s://localhost%s", GetVersionString(), protocol, serverPort)
	log.Printf("Authentication: %v", requireAuth)
	if requireAuth {
		log.Printf("  - Type: %s", map[bool]string{true: "Hash", false: "Plain"}[*passwordHash != ""])
	}
	log.Printf("Protocol: %s", strings.ToUpper(protocol))
	log.Printf("Supported languages: English (en), Français (fr)")
	log.Printf("Features:")
	log.Printf("  - Compression: XZ=%v, ZSTD=%v", server.hasCommand("xz"), server.hasCommand("zstd"))
	log.Printf("  - Checksum: %v", server.hasCommand("sha256sum"))
	
	if *useHTTPS {
		// Configure TLS
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		}

		srv := &http.Server{
			Addr:      serverPort,
			TLSConfig: tlsConfig,
		}

		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
			log.Fatalf("HTTPS server error: %v", err)
		}
	} else {
		if err := http.ListenAndServe(serverPort, nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}
}