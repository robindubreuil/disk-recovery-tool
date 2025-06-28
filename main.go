package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"strings"
	"sync"
	"time"
)

//go:embed templates/* locales/*
var embedFS embed.FS

// BlockDevice représente un périphérique de stockage
type BlockDevice struct {
	Name        string `json:"name"`
	Size        string `json:"size"`
	Type        string `json:"type"`
	Mountpoint  string `json:"mountpoint"`
	Description string `json:"description"`
}

// DumpOptions contient les options de dump
type DumpOptions struct {
	Device       string `json:"device"`
	Compression  string `json:"compression"`  // "xz" ou "zstd"
	Encrypt      bool   `json:"encrypt"`
	Password     string `json:"password"`
}

// DumpResult contient le résultat d'un dump
type DumpResult struct {
	Filename string `json:"filename"`
	Checksum string `json:"checksum"`
	Size     int64  `json:"size"`
	Duration string `json:"duration"`
}

// Translations contient les traductions pour une langue
type Translations map[string]string

// I18n gère l'internationalisation
type I18n struct {
	translations map[string]Translations
	defaultLang  string
}

// Session gère les sessions utilisateur
type Session struct {
	ID        string
	CreatedAt time.Time
	LastUsed  time.Time
}

// DiskRecoveryServer gère le serveur web
type DiskRecoveryServer struct {
	tmpl           *template.Template
	activeDumps    sync.Map
	requireAuth    bool
	passwordHash   string
	plainPassword  string
	sessions       map[string]*Session
	sessionsMutex  sync.RWMutex
	i18n           *I18n
}

func NewDiskRecoveryServer(requireAuth bool, password, passwordHash string) (*DiskRecoveryServer, error) {
	// Initialiser l'i18n
	i18n, err := NewI18n()
	if err != nil {
		return nil, fmt.Errorf("erreur initialisation i18n: %v", err)
	}

	// Créer les fonctions de template avec i18n
	funcMap := template.FuncMap{
		"t": func(key string, lang string) string {
			return i18n.Get(key, lang)
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(embedFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("erreur parsing templates: %v", err)
	}
	
	server := &DiskRecoveryServer{
		tmpl:        tmpl,
		requireAuth: requireAuth,
		sessions:    make(map[string]*Session),
		i18n:        i18n,
	}

	if requireAuth {
		if passwordHash != "" {
			server.passwordHash = passwordHash
		} else if password != "" {
			server.plainPassword = password
		} else {
			return nil, fmt.Errorf("mot de passe ou hash requis pour l'authentification")
		}
	}

	return server, nil
}

// NewI18n initialise le système d'internationalisation
func NewI18n() (*I18n, error) {
	i18n := &I18n{
		translations: make(map[string]Translations),
		defaultLang:  "en",
	}

	// Charger les traductions
	languages := []string{"en", "fr"}
	for _, lang := range languages {
		content, err := embedFS.ReadFile(fmt.Sprintf("locales/%s.json", lang))
		if err != nil {
			return nil, fmt.Errorf("erreur lecture locale %s: %v", lang, err)
		}

		var translations Translations
		if err := json.Unmarshal(content, &translations); err != nil {
			return nil, fmt.Errorf("erreur parsing locale %s: %v", lang, err)
		}

		i18n.translations[lang] = translations
	}

	return i18n, nil
}

// Get retourne une traduction
func (i *I18n) Get(key, lang string) string {
	if lang == "" {
		lang = i.defaultLang
	}

	if translations, exists := i.translations[lang]; exists {
		if value, exists := translations[key]; exists {
			return value
		}
	}

	// Fallback vers la langue par défaut
	if lang != i.defaultLang {
		if translations, exists := i.translations[i.defaultLang]; exists {
			if value, exists := translations[key]; exists {
				return value
			}
		}
	}

	// Fallback vers la clé elle-même
	return key
}

// DetectLanguage détecte la langue préférée du client
func (i *I18n) DetectLanguage(r *http.Request) string {
	// Vérifier cookie de langue
	if cookie, err := r.Cookie("lang"); err == nil {
		if _, exists := i.translations[cookie.Value]; exists {
			return cookie.Value
		}
	}

	// Vérifier header Accept-Language
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang != "" {
		parts := strings.Split(acceptLang, ",")
		for _, part := range parts {
			lang := strings.TrimSpace(strings.Split(part, ";")[0])
			if len(lang) >= 2 {
				shortLang := lang[:2]
				if _, exists := i.translations[shortLang]; exists {
					return shortLang
				}
			}
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

		// Vérifier session
		if s.isAuthenticated(r) {
			next(w, r)
			return
		}

		// Rediriger vers login
		if r.URL.Path != "/login" && r.URL.Path != "/auth" && r.URL.Path != "/set-lang" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next(w, r)
	}
}

// isAuthenticated vérifie si l'utilisateur est authentifié
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

	// Vérifier expiration (24h)
	if time.Since(session.LastUsed) > 24*time.Hour {
		s.sessionsMutex.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMutex.Unlock()
		return false
	}

	// Mettre à jour last used
	session.LastUsed = time.Now()
	return true
}

// generateSessionID génère un ID de session sécurisé
func (s *DiskRecoveryServer) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// loginHandler affiche la page de login
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
		http.Error(w, fmt.Sprintf("Erreur template: %v", err), http.StatusInternalServerError)
	}
}

// authHandler gère l'authentification
func (s *DiskRecoveryServer) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Mot de passe requis", http.StatusBadRequest)
		return
	}

	// Vérifier mot de passe
	valid := false
	if s.passwordHash != "" {
		// Vérifier hash (bcrypt ou crypt)
		valid = s.verifyPasswordHash(password, s.passwordHash)
	} else {
		// Comparaison en texte clair (constant time)
		valid = subtle.ConstantTimeCompare([]byte(password), []byte(s.plainPassword)) == 1
	}

	if !valid {
		time.Sleep(2 * time.Second) // Protection contre brute force
		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Créer session
	sessionID := s.generateSessionID()
	session := &Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	s.sessionsMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionsMutex.Unlock()

	// Cookie de session
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Mettre à true en HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   24 * 3600, // 24h
	})

	log.Printf("Authentification réussie pour session %s", sessionID[:8])
	http.Redirect(w, r, "/", http.StatusFound)
}

// verifyPasswordHash vérifie un hash de mot de passe
func (s *DiskRecoveryServer) verifyPasswordHash(password, hash string) bool {
	// Tenter bcrypt d'abord
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err == nil {
		return true
	}

	// Fallback vers crypt() Unix (format $6$ = SHA-512)
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

// setLangHandler change la langue
func (s *DiskRecoveryServer) setLangHandler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = "en"
	}

	// Vérifier que la langue existe
	if _, exists := s.i18n.translations[lang]; !exists {
		lang = "en"
	}

	// Cookie de langue
	http.SetCookie(w, &http.Cookie{
		Name:   "lang",
		Value:  lang,
		Path:   "/",
		MaxAge: 365 * 24 * 3600, // 1 an
	})

	// Rediriger vers referrer ou home
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/"
	}
	http.Redirect(w, r, referer, http.StatusFound)
}

// logoutHandler déconnecte l'utilisateur
func (s *DiskRecoveryServer) logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.sessionsMutex.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMutex.Unlock()
	}

	// Expirer cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

// getBlockDevices liste les périphériques de bloc disponibles
func (s *DiskRecoveryServer) getBlockDevices() ([]BlockDevice, error) {
	cmd := exec.Command("lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("erreur lsblk: %v", err)
	}

	var result struct {
		BlockDevices []BlockDevice `json:"blockdevices"`
	}
	
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("erreur parsing lsblk: %v", err)
	}

	// Filtre pour ne garder que les disques entiers (pas les partitions)
	var disks []BlockDevice
	for _, dev := range result.BlockDevices {
		if dev.Type == "disk" {
			// Ajoute une description plus claire
			dev.Description = fmt.Sprintf("%s (%s)", dev.Name, dev.Size)
			disks = append(disks, dev)
		}
	}

	return disks, nil
}

// validateDevice vérifie qu'un device est valide et sûr
func (s *DiskRecoveryServer) validateDevice(device string) error {
	// Validation stricte du nom de device
	matched, err := regexp.MatchString(`^[a-zA-Z0-9]+$`, device)
	if err != nil || !matched {
		return fmt.Errorf("nom de device invalide: %s", device)
	}

	// Vérifie que le device existe et est un device de bloc
	devicePath := "/dev/" + device
	info, err := os.Stat(devicePath)
	if err != nil {
		return fmt.Errorf("device non trouvé: %s", devicePath)
	}

	// Vérifie que c'est bien un device de bloc
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("pas un device de bloc: %s", devicePath)
	}

	return nil
}

// checkDependencies vérifie que les outils requis sont disponibles
func (s *DiskRecoveryServer) checkDependencies() error {
	required := []string{"dd", "lsblk", "sha256sum"}
	optional := map[string]string{
		"xz":      "compression XZ",
		"zstd":    "compression ZSTD", 
		"openssl": "chiffrement",
	}

	// Vérification des dépendances obligatoires
	for _, cmd := range required {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("commande requise non trouvée: %s", cmd)
		}
	}

	// Log des dépendances optionnelles
	for cmd, desc := range optional {
		if _, err := exec.LookPath(cmd); err != nil {
			log.Printf("Attention: %s non disponible (%s)", cmd, desc)
		}
	}

	return nil
}

// homeHandler affiche la page principale
func (s *DiskRecoveryServer) homeHandler(w http.ResponseWriter, r *http.Request) {
	devices, err := s.getBlockDevices()
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur listing devices: %v", err), http.StatusInternalServerError)
		return
	}

	lang := s.i18n.DetectLanguage(r)

	// Vérifier disponibilité des outils
	hasXz := s.hasCommand("xz")
	hasZstd := s.hasCommand("zstd")
	hasOpenssl := s.hasCommand("openssl")

	data := struct {
		Devices    []BlockDevice
		HasXz      bool
		HasZstd    bool
		HasOpenssl bool
		Lang       string
		Languages  map[string]string
	}{
		Devices:    devices,
		HasXz:      hasXz,
		HasZstd:    hasZstd,
		HasOpenssl: hasOpenssl,
		Lang:       lang,
		Languages: map[string]string{
			"en": "English",
			"fr": "Français",
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, fmt.Sprintf("Erreur template: %v", err), http.StatusInternalServerError)
	}
}

// hasCommand vérifie si une commande est disponible
func (s *DiskRecoveryServer) hasCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// [Continuité du code avec les handlers dump, restore, etc. - identiques à la version précédente]
// Je vais les omettre ici pour rester dans la limite de caractères, mais ils restent identiques

// dumpHandler gère le dump et streaming d'un disque
func (s *DiskRecoveryServer) dumpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Parse options
	options := DumpOptions{
		Device:      r.FormValue("device"),
		Compression: r.FormValue("compression"),
		Encrypt:     r.FormValue("encrypt") == "on",
		Password:    r.FormValue("password"),
	}

	// Validation
	if options.Device == "" {
		http.Error(w, "Device requis", http.StatusBadRequest)
		return
	}

	if err := s.validateDevice(options.Device); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if options.Encrypt && options.Password == "" {
		http.Error(w, "Mot de passe requis pour le chiffrement", http.StatusBadRequest)
		return
	}

	if !s.hasCommand(options.Compression) {
		http.Error(w, fmt.Sprintf("Outil de compression non disponible: %s", options.Compression), http.StatusBadRequest)
		return
	}

	devicePath := "/dev/" + options.Device
	
	log.Printf("Début du dump de %s (compression: %s, chiffrement: %v)", 
		devicePath, options.Compression, options.Encrypt)

	timestamp := time.Now().Format("20060102_150405")
	extension := fmt.Sprintf(".img.%s", options.Compression)
	if options.Encrypt {
		extension += ".enc"
	}
	filename := fmt.Sprintf("disk_%s_%s%s", options.Device, timestamp, extension)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Cache-Control", "no-cache")

	result, err := s.streamDiskDump(w, devicePath, options, filename)
	if err != nil {
		log.Printf("Erreur dump %s: %v", devicePath, err)
		return
	}

	log.Printf("Fin du dump de %s - Checksum: %s", devicePath, result.Checksum)
}

// [streamDiskDump, restoreHandler, etc. restent identiques...]

// statusHandler fournit des informations sur le serveur
func (s *DiskRecoveryServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	status := map[string]interface{}{
		"status":      "ready",
		"timestamp":   time.Now().Unix(),
		"version":     "2.1.0",
		"auth":        s.requireAuth,
		"features": map[string]bool{
			"xz_compression":      s.hasCommand("xz"),
			"zstd_compression":   s.hasCommand("zstd"),
			"encryption":         s.hasCommand("openssl"),
			"checksum":           s.hasCommand("sha256sum"),
		},
	}
	
	json.NewEncoder(w).Encode(status)
}

// streamDiskDump exécute le pipeline complet et streame vers l'HTTP response
func (s *DiskRecoveryServer) streamDiskDump(w http.ResponseWriter, devicePath string, options DumpOptions, filename string) (*DumpResult, error) {
	startTime := time.Now()

	// Commande dd pour lire le disque
	ddCmd := exec.Command("dd", "if="+devicePath, "bs=1M", "status=none")
	
	// Commande de compression
	var compCmd *exec.Cmd
	switch options.Compression {
	case "xz":
		compCmd = exec.Command("xz")
	case "zstd":
		compCmd = exec.Command("zstd")
	default:
		return nil, fmt.Errorf("compression non supportée: %s", options.Compression)
	}

	// Pipeline de base: dd → compression
	ddToComp, ddWriter := io.Pipe()
	ddCmd.Stdout = ddWriter
	ddCmd.Stderr = os.Stderr

	compCmd.Stdin = ddToComp
	compCmd.Stderr = os.Stderr

	var finalReader io.Reader
	var finalCmd *exec.Cmd

	if options.Encrypt {
		// Pipeline: dd → compression → chiffrement
		compToNext, nextWriter := io.Pipe()
		compCmd.Stdout = nextWriter

		// Commande de chiffrement avec OpenSSL
		encCmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-pass", "stdin")
		
		// Setup stdin pour le mot de passe
		passwordPipe, passwordWriter := io.Pipe()
		go func() {
			defer passwordWriter.Close()
			passwordWriter.Write([]byte(options.Password))
		}()
		
		// Combiner password et données
		encCmd.Stdin = io.MultiReader(passwordPipe, compToNext)
		encCmd.Stderr = os.Stderr

		finalReader, _ = encCmd.StdoutPipe()
		finalCmd = encCmd
		
		// Gérer la fermeture du pipe intermédiaire
		go func() {
			compCmd.Wait()
			nextWriter.Close()
		}()
	} else {
		// Pipeline: dd → compression → sortie
		finalReader, _ = compCmd.StdoutPipe()
		finalCmd = compCmd
	}

	// Calcul du checksum en parallèle avec TeeReader
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

	// Copie vers HTTP response
	var bytesWritten int64
	copyDone := make(chan error, 1)
	go func() {
		defer checksumWriter.Close()
		n, err := io.Copy(w, teeReader)
		bytesWritten = n
		copyDone <- err
	}()

	// Démarrage ordonné des commandes
	if err := ddCmd.Start(); err != nil {
		return nil, fmt.Errorf("erreur démarrage dd: %v", err)
	}
	
	if err := compCmd.Start(); err != nil {
		return nil, fmt.Errorf("erreur démarrage compression: %v", err)
	}

	if finalCmd != compCmd {
		if err := finalCmd.Start(); err != nil {
			return nil, fmt.Errorf("erreur démarrage chiffrement: %v", err)
		}
	}

	// Gestion de la fermeture ordonnée des pipes
	go func() {
		ddCmd.Wait()
		ddWriter.Close()
	}()

	if finalCmd != compCmd {
		// Cas du chiffrement - compCmd se ferme automatiquement via la goroutine ci-dessus
		go func() {
			finalCmd.Wait()
		}()
	} else {
		// Cas sans chiffrement - attendre compCmd
		go func() {
			compCmd.Wait()
		}()
	}

	// Attendre la fin de la copie
	if err := <-copyDone; err != nil {
		return nil, fmt.Errorf("erreur copie HTTP: %v", err)
	}

	// Récupérer le checksum
	checksum := <-checksumDone
	duration := time.Since(startTime)

	result := &DumpResult{
		Filename: filename,
		Checksum: checksum,
		Size:     bytesWritten,
		Duration: duration.String(),
	}

	// Log du résultat avec audit
	log.Printf("[AUDIT] Dump terminé - Fichier: %s, Taille: %d bytes, Checksum: %s, Durée: %s",
		result.Filename, result.Size, result.Checksum, result.Duration)

	return result, nil
}

// restoreHandler gère la restauration d'image sur un disque
func (s *DiskRecoveryServer) restoreHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (32MB max pour headers)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Erreur parsing form", http.StatusBadRequest)
		return
	}

	device := r.FormValue("restore_device")
	password := r.FormValue("restore_password")
	
	file, header, err := r.FormFile("image_file")
	if err != nil {
		http.Error(w, "Fichier requis", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if device == "" {
		http.Error(w, "Device de destination requis", http.StatusBadRequest)
		return
	}

	if err := s.validateDevice(device); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	devicePath := "/dev/" + device
	filename := header.Filename

	log.Printf("[AUDIT] Début restauration de %s vers %s", filename, devicePath)

	// Détection du type de fichier
	isEncrypted := strings.Contains(filename, ".enc")
	isXz := strings.Contains(filename, ".xz")
	isZstd := strings.Contains(filename, ".zst")

	if isEncrypted && password == "" {
		http.Error(w, "Mot de passe requis pour fichier chiffré", http.StatusBadRequest)
		return
	}

	// Pipeline de restauration
	if err := s.restoreFromStream(file, devicePath, isEncrypted, isXz, isZstd, password); err != nil {
		log.Printf("[AUDIT] Erreur restauration %s → %s: %v", filename, devicePath, err)
		http.Error(w, fmt.Sprintf("Erreur restauration: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUDIT] Restauration terminée: %s → %s", filename, devicePath)
	
	// Réponse JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Restauration terminée sur %s", devicePath),
	})
}

// restoreFromStream exécute le pipeline de restauration
func (s *DiskRecoveryServer) restoreFromStream(input io.Reader, devicePath string, isEncrypted, isXz, isZstd bool, password string) error {
	var currentReader io.Reader = input
	var commands []*exec.Cmd

	// Étape 1: Déchiffrement si nécessaire
	if isEncrypted {
		decCmd := exec.Command("openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", "stdin")
		
		// Setup password pipe
		passwordPipe, passwordWriter := io.Pipe()
		go func() {
			defer passwordWriter.Close()
			passwordWriter.Write([]byte(password))
		}()
		
		decCmd.Stdin = io.MultiReader(passwordPipe, currentReader)
		decCmd.Stderr = os.Stderr
		
		decReader, err := decCmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("erreur pipe déchiffrement: %v", err)
		}
		
		if err := decCmd.Start(); err != nil {
			return fmt.Errorf("erreur démarrage déchiffrement: %v", err)
		}
		
		currentReader = decReader
		commands = append(commands, decCmd)
	}

	// Étape 2: Décompression
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
			return fmt.Errorf("erreur pipe décompression: %v", err)
		}
		
		if err := decompCmd.Start(); err != nil {
			return fmt.Errorf("erreur démarrage décompression: %v", err)
		}
		
		currentReader = decompReader
		commands = append(commands, decompCmd)
	}

	// Étape 3: Écriture sur disque avec dd
	ddCmd := exec.Command("dd", "of="+devicePath, "bs=1M", "status=none")
	ddCmd.Stdin = currentReader
	ddCmd.Stderr = os.Stderr

	if err := ddCmd.Run(); err != nil {
		return fmt.Errorf("erreur dd: %v", err)
	}

	// Attendre la fin de tous les processus
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("erreur pipeline: %v", err)
		}
	}

	return nil
}

func main() {
	// Arguments CLI
	var (
		port         = flag.String("port", "8080", "Port d'écoute du serveur")
		password     = flag.String("password", "", "Mot de passe en clair pour l'authentification")
		passwordHash = flag.String("password-hash", "", "Hash du mot de passe (bcrypt ou crypt)")
		help         = flag.Bool("help", false, "Afficher l'aide")
	)
	flag.Parse()

	if *help {
		fmt.Printf("Disk Recovery Tool v2.1.0 - Dump & Restore avec authentification et i18n\n\n")
		fmt.Printf("Usage: %s [options]\n\n", os.Args[0])
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
		fmt.Printf("\nExemples:\n")
		fmt.Printf("  # Serveur sans authentification\n")
		fmt.Printf("  sudo %s\n\n", os.Args[0])
		fmt.Printf("  # Avec mot de passe\n")
		fmt.Printf("  sudo %s -password mypassword\n\n", os.Args[0])
		fmt.Printf("  # Avec hash bcrypt\n")
		fmt.Printf("  sudo %s -password-hash '$2y$10$...'\n\n", os.Args[0])
		fmt.Printf("  # Avec hash crypt Unix\n")
		fmt.Printf("  sudo %s -password-hash '$6$salt$hash...'\n\n", os.Args[0])
		return
	}

	// Vérification des privilèges root
	if os.Geteuid() != 0 {
		log.Fatal("Ce programme doit être exécuté en tant que root pour accéder aux devices de bloc")
	}

	// Déterminer si l'authentification est requise
	requireAuth := *password != "" || *passwordHash != ""

	server, err := NewDiskRecoveryServer(requireAuth, *password, *passwordHash)
	if err != nil {
		log.Fatalf("Erreur création serveur: %v", err)
	}

	// Vérification des dépendances
	if err := server.checkDependencies(); err != nil {
		log.Fatalf("Dépendances manquantes: %v", err)
	}

	// Routes avec middleware d'authentification
	http.HandleFunc("/login", server.loginHandler)
	http.HandleFunc("/auth", server.authHandler)
	http.HandleFunc("/logout", server.logoutHandler)
	http.HandleFunc("/set-lang", server.setLangHandler)
	http.HandleFunc("/", server.authMiddleware(server.homeHandler))
	http.HandleFunc("/dump", server.authMiddleware(server.dumpHandler))
	http.HandleFunc("/restore", server.authMiddleware(server.restoreHandler))
	http.HandleFunc("/status", server.statusHandler)

	serverPort := ":" + *port
	log.Printf("Disk Recovery Tool v2.1.0 démarré sur http://localhost%s", serverPort)
	log.Printf("Authentification: %v", requireAuth)
	if requireAuth {
		log.Printf("  - Type: %s", map[bool]string{true: "Hash", false: "Plain"}[*passwordHash != ""])
	}
	log.Printf("Langues supportées: Français (fr), English (en)")
	log.Printf("Fonctionnalités:")
	log.Printf("  - Compression: XZ=%v, ZSTD=%v", server.hasCommand("xz"), server.hasCommand("zstd"))
	log.Printf("  - Chiffrement: %v", server.hasCommand("openssl"))
	log.Printf("  - Checksum: %v", server.hasCommand("sha256sum"))
	
	if err := http.ListenAndServe(serverPort, nil); err != nil {
		log.Fatalf("Erreur serveur HTTP: %v", err)
	}
}

// streamDiskDump, restoreFromStream, restoreHandler - identiques à v2.0
// [Code omis pour économiser l'espace, mais ils restent identiques]