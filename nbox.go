package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"image/color"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// paddingBlockSize is the block size used for ISO-style padding.
const paddingBlockSize = 4096

// Argon2id parameters for deriving the vault key.
// Tuned for 2026 hardware: 128 MiB memory makes GPU/ASIC brute-force
// economically unfeasible for most attackers.
const (
	argon2Time    = 4
	argon2Memory  = 128 * 1024 // 128 MiB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
)

// NIST SP 800-63B: minimum 15 characters for memorized secrets.
const minPassphraseLen = 15

// Rate limiting for passphrase decryption attempts.
// The counter is persisted in the vault header so it survives restarts.
const (
	maxDecryptAttempts = 5
	rateLimitDuration  = time.Minute
)

// Security timers.
const (
	// autoLockDuration: 15 minutes is a better balance for real-world usage.
	// It prevents unattended access but doesn't interrupt normal thinking/typing breaks.
	autoLockDuration = 15 * time.Minute

	// clipboardClearDelay: 45 seconds gives the user enough time to switch 
	// windows and paste the text into a potentially slow email client or messenger,
	// while still protecting against casual clipboard snooping.
	clipboardClearDelay = 45 * time.Second

	// autoLockCheckInterval: Keep this at 5 seconds for responsive locking.
	autoLockCheckInterval = 5 * time.Second
)

// vaultFile is the single encrypted file that holds all keys.
const vaultFile = "vault.enc"

// portableMarker is a marker file next to the executable that signals
// portable mode on Windows.
const portableMarker = ".Nbox-portable"

// vaultMagic is the versioned header prefix. It allows future format
// migrations and protects against downgrade attacks.
const vaultMagic = "Nbox v1\n"

// vaultHeaderLen is the total length of the unencrypted vault header:
// magic (11) + attempts (4) + lastAttemptUnix (8) + salt (16) = 39 bytes.
const vaultHeaderLen = len(vaultMagic) + 4 + 8 + saltLen

// Entity represents a NaCl keypair (identity) or a public key (peer).
type entity struct {
	pub, sec *[32]byte
	name     string
}

func (e *entity) isIdentity() bool { return e.pub != nil && e.sec != nil }
func (e *entity) isPeer() bool     { return e.pub != nil && e.sec == nil }

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9-_]+$`)

// Theme
type orangeTheme struct {
	base fyne.Theme
}

func (p *orangeTheme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(s)
}

func (p *orangeTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 255, G: 165, B: 0, A: 255}
	case theme.ColorNameForegroundOnPrimary:
		return color.White
	case theme.ColorNameHyperlink:
		return color.NRGBA{R: 255, G: 165, B: 0, A: 255}
	default:
		return p.base.Color(name, variant)
	}
}

func (p *orangeTheme) Icon(name fyne.ThemeIconName) fyne.Resource { return p.base.Icon(name) }
func (p *orangeTheme) Size(name fyne.ThemeSizeName) float32      { return p.base.Size(name) }

// ScrollableEntry
type ScrollableEntry struct {
	widget.BaseWidget
	internal *widget.Entry
}

func NewScrollableEntry() *ScrollableEntry {
	se := &ScrollableEntry{}
	se.internal = widget.NewMultiLineEntry()
	se.internal.Wrapping = fyne.TextWrapOff
	se.internal.TextStyle = fyne.TextStyle{Monospace: true}
	se.ExtendBaseWidget(se)
	return se
}

func (se *ScrollableEntry) SetText(text string)          { se.internal.SetText(text) }
func (se *ScrollableEntry) GetText() string              { return se.internal.Text }
func (se *ScrollableEntry) SetPlaceHolder(text string)   { se.internal.SetPlaceHolder(text) }
func (se *ScrollableEntry) SetOnChanged(fn func(string)) { se.internal.OnChanged = fn }
func (se *ScrollableEntry) Entry() *widget.Entry         { return se.internal }

func (se *ScrollableEntry) CreateRenderer() fyne.WidgetRenderer {
	return &scrollableEntryRenderer{se: se}
}

type scrollableEntryRenderer struct{ se *ScrollableEntry }

func (r *scrollableEntryRenderer) Layout(size fyne.Size) { r.se.internal.Resize(size) }
func (r *scrollableEntryRenderer) MinSize() fyne.Size    { return r.se.internal.MinSize() }
func (r *scrollableEntryRenderer) Refresh()              { r.se.internal.Refresh() }
func (r *scrollableEntryRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.se.internal}
}
func (r *scrollableEntryRenderer) Destroy() {}

// Base64 armor (76 chars per line, no trailing newline)
func armorBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		if end < len(encoded) {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func dearmorBase64(input string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, input)
	return base64.StdEncoding.DecodeString(cleaned)
}

// Padding (ISO-style)
func addISOPadding(data []byte, blockSize int) []byte {
	remainder := len(data) % blockSize
	if remainder == 0 {
		return data
	}
	paddingNeeded := blockSize - remainder
	padded := make([]byte, len(data)+paddingNeeded)
	copy(padded, data)
	padded[len(data)] = 0x80
	return padded
}

func removeISOPadding(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}
	if len(data)%blockSize != 0 {
		return data
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i]
		}
		if data[i] != 0x00 {
			break
		}
	}
	return data
}

// Vault paths
func vaultDir() string {
	if d := os.Getenv("NboxDIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if dir, ok := portableDir(); ok {
			return dir
		}
	}
	root := fyne.CurrentApp().Storage().RootURI()
	if root == nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".nbox")
	}
	return root.Path()
}

func portableDir() (string, bool) {
	if runtime.GOOS != "windows" {
		return "", false
	}
	exePath, err := os.Executable()
	if err != nil {
		return "", false
	}
	exeDir := filepath.Dir(exePath)
	marker := filepath.Join(exeDir, portableMarker)
	if _, err := os.Stat(marker); err == nil {
		return filepath.Join(exeDir, ".nbox"), true
	}
	return "", false
}

func setPortableMode() error {
	if runtime.GOOS != "windows" {
		return errors.New("portable mode is only available on Windows")
	}
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	marker := filepath.Join(filepath.Dir(exePath), portableMarker)
	return os.WriteFile(marker, []byte("portable"), 0600)
}

func vaultPath() string {
	return filepath.Join(vaultDir(), vaultFile)
}

func vaultExists() bool {
	_, err := os.Stat(vaultPath())
	return err == nil
}

// Vault crypto: Argon2id + NaCl secretbox
func deriveKey(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

func packMap(entries map[string][]byte) []byte {
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf []byte
	for _, name := range names {
		content := entries[name]
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(name)))
		buf = append(buf, lenBuf...)
		buf = append(buf, []byte(name)...)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(content)))
		buf = append(buf, lenBuf...)
		buf = append(buf, content...)
	}
	return buf
}

func unpackMap(data []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	offset := 0
	for offset < len(data) {
		if offset+4 > len(data) {
			return nil, errors.New("corrupted vault data")
		}
		nameLen := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if offset+nameLen > len(data) {
			return nil, errors.New("corrupted vault data")
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen
		if offset+4 > len(data) {
			return nil, errors.New("corrupted vault data")
		}
		contentLen := int(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if offset+contentLen > len(data) {
			return nil, errors.New("corrupted vault data")
		}
		content := data[offset : offset+contentLen]
		offset += contentLen
		result[name] = append([]byte(nil), content...)
	}
	return result, nil
}

// parseVaultBlob parses the raw vault file with the versioned header.
func parseVaultBlob(data []byte) (attempts uint32, lastAttempt int64, salt []byte, encrypted []byte, err error) {
	if len(data) < vaultHeaderLen {
		return 0, 0, nil, nil, errors.New("vault blob too short")
	}
	if string(data[:len(vaultMagic)]) != vaultMagic {
		return 0, 0, nil, nil, errors.New("invalid vault format: missing version header")
	}
	offset := len(vaultMagic)
	attempts = binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	lastAttempt = int64(binary.LittleEndian.Uint64(data[offset:]))
	offset += 8
	salt = make([]byte, saltLen)
	copy(salt, data[offset:offset+saltLen])
	offset += saltLen
	encrypted = make([]byte, len(data)-offset)
	copy(encrypted, data[offset:])
	return attempts, lastAttempt, salt, encrypted, nil
}

// buildVaultBlob constructs the on-disk vault blob with the versioned
// header containing the persisted lockout counter.
func buildVaultBlob(salt []byte, encrypted []byte, attempts uint32, lastAttempt int64) []byte {
	buf := make([]byte, 0, vaultHeaderLen+len(encrypted))
	buf = append(buf, []byte(vaultMagic)...)
	attemptsBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(attemptsBuf, attempts)
	buf = append(buf, attemptsBuf...)
	lastAttemptBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(lastAttemptBuf, uint64(lastAttempt))
	buf = append(buf, lastAttemptBuf...)
	buf = append(buf, salt...)
	buf = append(buf, encrypted...)
	return buf
}

// encryptVault encrypts the entries map. It returns the salt and the
// nonce+ciphertext separately so the caller can build the full blob
// with the versioned header.
// NOTE: memguard.NewBufferFromBytes automatically zeroes the source
// slice after copying, so manual zeroing loops are unnecessary.
func encryptVault(entries map[string][]byte, passphrase *memguard.LockedBuffer) (salt []byte, encrypted []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	rawKey := deriveKey(passphrase.Bytes(), salt)
	keyBuf := memguard.NewBufferFromBytes(rawKey) // zeroes rawKey internally
	defer keyBuf.Destroy()

	var secretKey [32]byte
	copy(secretKey[:], keyBuf.Bytes())

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}

	packed := packMap(entries)
	packedBuf := memguard.NewBufferFromBytes(packed) // zeroes packed internally
	defer packedBuf.Destroy()

	encrypted = secretbox.Seal(nonce[:], packedBuf.Bytes(), &nonce, &secretKey)
	return salt, encrypted, nil
}

// decryptVault decrypts the ciphertext using the given salt and passphrase.
func decryptVault(salt []byte, encrypted []byte, passphrase *memguard.LockedBuffer) (map[string][]byte, error) {
	if len(encrypted) < 24 {
		return nil, errors.New("ciphertext too short")
	}
	rawKey := deriveKey(passphrase.Bytes(), salt)
	keyBuf := memguard.NewBufferFromBytes(rawKey) // zeroes rawKey internally
	defer keyBuf.Destroy()

	var secretKey [32]byte
	copy(secretKey[:], keyBuf.Bytes())

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	ciphertext := encrypted[24:]

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &secretKey)
	if !ok {
		return nil, errors.New("authentication failed: incorrect passphrase or corrupted vault")
	}
	plainBuf := memguard.NewBufferFromBytes(plaintext) // zeroes plaintext internally
	defer plainBuf.Destroy()

	return unpackMap(plainBuf.Bytes())
}

// saveVault encrypts and writes the vault to disk, including the
// versioned header with the persisted lockout counter.
func saveVault(entries map[string][]byte, passphrase *memguard.LockedBuffer, attempts uint32, lastAttempt int64) error {
	salt, encrypted, err := encryptVault(entries, passphrase)
	if err != nil {
		return err
	}
	blob := buildVaultBlob(salt, encrypted, attempts, lastAttempt)
	if err := os.MkdirAll(vaultDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(vaultPath(), blob, 0600)
}

// loadVault reads and decrypts the vault. It returns the entries along
// with the persisted lockout state.
func loadVault(passphrase *memguard.LockedBuffer) (map[string][]byte, uint32, int64, error) {
	data, err := os.ReadFile(vaultPath())
	if err != nil {
		return nil, 0, 0, err
	}
	attempts, lastAttempt, salt, encrypted, err := parseVaultBlob(data)
	if err != nil {
		return nil, 0, 0, err
	}
	entries, err := decryptVault(salt, encrypted, passphrase)
	if err != nil {
		return nil, 0, 0, err
	}
	return entries, attempts, lastAttempt, nil
}

// loadVaultLockout reads only the header of the vault file to restore
// the persisted lockout counter without requiring the passphrase.
func loadVaultLockout() (uint32, int64, error) {
	data, err := os.ReadFile(vaultPath())
	if err != nil {
		return 0, 0, err
	}
	attempts, lastAttempt, _, _, err := parseVaultBlob(data)
	if err != nil {
		return 0, 0, err
	}
	return attempts, lastAttempt, nil
}

// Application
type NboxApp struct {
	app         fyne.App
	window      fyne.Window
	textArea    *ScrollableEntry
	statusLabel *widget.Label
	isDarkTheme bool
	themeSwitch *widget.Button
	infoBtn     *widget.Button
	clearBtn    *widget.Button
	deleteBtn   *widget.Button
	importBtn   *widget.Button
	exportBtn   *widget.Button

	scannedPubKey string

	mu              sync.Mutex
	decryptAttempts int
	lastAttempt     time.Time

	vaultMu       sync.RWMutex
	vaultEntries  map[string][]byte
	vaultPass     *memguard.LockedBuffer
	vaultUnlocked bool

	// lastActivity is a Unix-nano timestamp updated by touchActivity().
	// The auto-lock goroutine reads it to decide whether to lock the vault.
	lastActivity atomic.Int64

	// clipboardValue stores the last value we copied via secureCopy, so that
	// the auto-clear goroutine can verify the clipboard still holds it before
	// wiping (avoiding clobbering user-copied data).
	clipboardMu    sync.Mutex
	clipboardValue string
}

// touchActivity updates the inactivity timestamp. Call this whenever the user
// performs an action that should postpone the auto-lock.
func (a *NboxApp) touchActivity() {
	a.lastActivity.Store(time.Now().UnixNano())
}

// secureCopy copies text to the clipboard and schedules an automatic wipe
// after clipboardClearDelay. The wipe only happens if the clipboard still
// contains the exact text we copied.
// NOTE: OS-level clipboard managers (Windows Clipboard History, KDE Connect,
// Ditto, etc.) may intercept and persist the text before we can wipe it.
func (a *NboxApp) secureCopy(text string) {
	a.window.Clipboard().SetContent(text)
	a.clipboardMu.Lock()
	a.clipboardValue = text
	a.clipboardMu.Unlock()

	go func() {
		time.Sleep(clipboardClearDelay)
		a.clipboardMu.Lock()
		expected := a.clipboardValue
		a.clipboardMu.Unlock()
		if expected == "" {
			return
		}
		if a.window != nil && a.window.Clipboard() != nil {
			if a.window.Clipboard().Content() == expected {
				a.window.Clipboard().SetContent("")
			}
		}
		a.clipboardMu.Lock()
		if a.clipboardValue == expected {
			a.clipboardValue = ""
		}
		a.clipboardMu.Unlock()
	}()
}

// saveVaultLockout updates only the lockout counter in the vault header
// without re-encrypting the entire vault. This is fast and keeps the
// persisted rate-limit in sync after each passphrase attempt.
func (a *NboxApp) saveVaultLockout() {
	data, err := os.ReadFile(vaultPath())
	if err != nil {
		return
	}
	_, _, salt, encrypted, err := parseVaultBlob(data)
	if err != nil {
		return
	}
	a.mu.Lock()
	attempts := uint32(a.decryptAttempts)
	lastAttempt := a.lastAttempt.Unix()
	a.mu.Unlock()
	blob := buildVaultBlob(salt, encrypted, attempts, lastAttempt)
	_ = os.WriteFile(vaultPath(), blob, 0600)
}

// In-memory vault helpers
func (a *NboxApp) listIdentities() []string {
	a.vaultMu.RLock()
	defer a.vaultMu.RUnlock()
	var out []string
	for name, content := range a.vaultEntries {
		e := parseEntityFromPEM(name, content)
		if e != nil && e.isIdentity() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (a *NboxApp) listPeers() []string {
	a.vaultMu.RLock()
	defer a.vaultMu.RUnlock()
	var out []string
	for name, content := range a.vaultEntries {
		e := parseEntityFromPEM(name, content)
		if e != nil && e.isPeer() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (a *NboxApp) getEntity(name string) *entity {
	a.vaultMu.RLock()
	defer a.vaultMu.RUnlock()
	content, ok := a.vaultEntries[name]
	if !ok {
		return nil
	}
	return parseEntityFromPEM(name, content)
}

func (a *NboxApp) putEntity(name string, pemData []byte) {
	a.vaultMu.Lock()
	defer a.vaultMu.Unlock()
	a.vaultEntries[name] = append([]byte(nil), pemData...)
}

func (a *NboxApp) deleteEntity(name string) {
	a.vaultMu.Lock()
	defer a.vaultMu.Unlock()
	delete(a.vaultEntries, name)
}

func parseEntityFromPEM(name string, data []byte) *entity {
	e := &entity{name: name}
	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "NaClbox SECRET KEY":
			e.sec = new([32]byte)
			copy(e.sec[:], block.Bytes)
		case "NaClbox PUBLIC KEY":
			e.pub = new([32]byte)
			copy(e.pub[:], block.Bytes)
		}
		rest = remainder
	}
	if e.pub == nil && e.sec == nil {
		return nil
	}
	return e
}

// Passphrase dialogs
func (a *NboxApp) askPassphrase(title, okLabel string, callback func(*memguard.LockedBuffer)) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder(fmt.Sprintf(""))
	passEntry.Validator = func(s string) error {
		if len([]rune(s)) < minPassphraseLen {
			return fmt.Errorf("passphrase must be at least %d characters", minPassphraseLen)
		}
		return nil
	}
	items := []*widget.FormItem{widget.NewFormItem("Passphrase", passEntry)}
	dialog.ShowForm(title, okLabel, "Cancel", items, func(confirmed bool) {
		if !confirmed {
			return
		}
		if err := passEntry.Validate(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}
		buf := memguard.NewBufferFromBytes([]byte(passEntry.Text))
		passEntry.SetText("")
		passEntry.Refresh()
		a.touchActivity()
		callback(buf)
	}, a.window)
}

func (a *NboxApp) askPassphraseConfirm(title string, callback func(*memguard.LockedBuffer)) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder(fmt.Sprintf(""))
	passEntry.Validator = func(s string) error {
		if len([]rune(s)) < minPassphraseLen {
			return fmt.Errorf("passphrase must be at least %d characters", minPassphraseLen)
		}
		return nil
	}
	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("")
	items := []*widget.FormItem{
		widget.NewFormItem("Passphrase", passEntry),
		widget.NewFormItem("Confirm", confirmEntry),
	}
	dialog.ShowForm(title, "OK", "Cancel", items, func(confirmed bool) {
		if !confirmed {
			return
		}
		if err := passEntry.Validate(); err != nil {
			dialog.ShowError(err, a.window)
			return
		}
		if passEntry.Text != confirmEntry.Text {
			dialog.ShowError(errors.New("passphrases do not match"), a.window)
			return
		}
		buf := memguard.NewBufferFromBytes([]byte(passEntry.Text))
		passEntry.SetText("")
		confirmEntry.SetText("")
		a.touchActivity()
		callback(buf)
	}, a.window)
}

// Vault lifecycle
func (a *NboxApp) ensureVaultUnlocked(callback func()) {
	a.vaultMu.RLock()
	unlocked := a.vaultUnlocked
	a.vaultMu.RUnlock()
	if unlocked {
		a.touchActivity()
		callback()
		return
	}
	if !vaultExists() {
		if runtime.GOOS == "windows" {
			a.askVaultLocation(func() {
				a.createNewVault(callback)
			})
			return
		}
		a.createNewVault(callback)
		return
	}
	a.askPassphrase("Unlock Vault", "Unlock", func(pass *memguard.LockedBuffer) {
		// Check persisted rate limit BEFORE attempting decryption.
		a.mu.Lock()
		now := time.Now()
		if now.Sub(a.lastAttempt) > rateLimitDuration {
			a.decryptAttempts = 0
		}
		a.lastAttempt = now
		if a.decryptAttempts >= maxDecryptAttempts {
			a.mu.Unlock()
			pass.Destroy()
			dialog.ShowError(errors.New("rate limited: too many failed passphrase attempts"), a.window)
			return
		}
		a.mu.Unlock()

		entries, attempts, lastAttempt, err := loadVault(pass)
		if err != nil {
			pass.Destroy()
			// Persist the failed attempt counter
			a.mu.Lock()
			a.decryptAttempts++
			a.lastAttempt = time.Now()
			a.mu.Unlock()
			a.saveVaultLockout()
			dialog.ShowError(err, a.window)
			return
		}

		// Success: reset the persisted counter
		a.mu.Lock()
		a.decryptAttempts = 0
		a.lastAttempt = time.Time{}
		a.mu.Unlock()

		a.vaultMu.Lock()
		a.vaultEntries = entries
		a.vaultPass = pass
		a.vaultUnlocked = true
		a.vaultMu.Unlock()

		// Sync the counter from disk in case it was updated elsewhere
		a.mu.Lock()
		a.decryptAttempts = int(attempts)
		a.lastAttempt = time.Unix(lastAttempt, 0)
		a.mu.Unlock()
		a.saveVaultLockout()
		a.touchActivity()
		a.statusLabel.SetText("Vault unlocked")
		callback()
	})
}

func (a *NboxApp) askVaultLocation(callback func()) {
	if runtime.GOOS != "windows" {
		callback()
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		callback()
		return
	}
	exeDir := filepath.Dir(exePath)
	marker := filepath.Join(exeDir, portableMarker)
	if _, err := os.Stat(marker); err == nil {
		callback()
		return
	}
	if _, err := os.Stat(filepath.Join(exeDir, ".Nbox", vaultFile)); err == nil {
		callback()
		return
	}
	dialog.ShowConfirm(
		"Vault Location",
		"Store the vault next to the executable (portable mode)?\n\n"+
			"Yes  → Portable (USB stick friendly)\n"+
			"No   → Standard user directory",
		func(portable bool) {
			if portable {
				if err := setPortableMode(); err != nil {
					dialog.ShowError(err, a.window)
				}
			}
			callback()
		},
		a.window,
	)
}

func (a *NboxApp) createNewVault(callback func()) {
	a.askPassphraseConfirm("Create Vault Passphrase", func(pass *memguard.LockedBuffer) {
		a.vaultMu.Lock()
		a.vaultEntries = map[string][]byte{}
		a.vaultPass = pass
		a.vaultUnlocked = true
		a.vaultMu.Unlock()

		a.mu.Lock()
		a.decryptAttempts = 0
		a.lastAttempt = time.Time{}
		a.mu.Unlock()

		if err := saveVault(map[string][]byte{}, pass, 0, 0); err != nil {
			dialog.ShowError(err, a.window)
			a.vaultMu.Lock()
			a.vaultUnlocked = false
			a.vaultMu.Unlock()
			return
		}
		a.touchActivity()
		a.statusLabel.SetText("New vault created at " + vaultDir())
		callback()
	})
}

func (a *NboxApp) persistVault() {
	a.vaultMu.RLock()
	pass := a.vaultPass
	entries := a.vaultEntries
	unlocked := a.vaultUnlocked
	a.vaultMu.RUnlock()
	if !unlocked || pass == nil {
		return
	}
	a.mu.Lock()
	attempts := uint32(a.decryptAttempts)
	lastAttempt := a.lastAttempt.Unix()
	a.mu.Unlock()

	snapshot := make(map[string][]byte, len(entries))
	for k, v := range entries {
		snapshot[k] = v
	}
	if err := saveVault(snapshot, pass, attempts, lastAttempt); err != nil {
		dialog.ShowError(err, a.window)
	}
}

// lockVault wipes the in-memory vault and destroys the passphrase buffer.
// The on-disk vault.enc remains untouched. The persisted lockout counter
// is NOT reset here, because it tracks passphrase failures, not inactivity.
func (a *NboxApp) lockVault() {
	a.vaultMu.Lock()
	if a.vaultPass != nil {
		a.vaultPass.Destroy()
		a.vaultPass = nil
	}
	// Overwrite and drop the in-memory entries.
	for k := range a.vaultEntries {
		if content, ok := a.vaultEntries[k]; ok {
			for i := range content {
				content[i] = 0
			}
		}
		delete(a.vaultEntries, k)
	}
	a.vaultEntries = map[string][]byte{}
	a.vaultUnlocked = false
	a.vaultMu.Unlock()

	// Also wipe the text area and clipboard to be safe.
	// NOTE: Go strings are immutable; Fyne's widget.Entry stores text
	// internally as a Go string, so a perfect RAM wipe of displayed
	// plaintext is not achievable. This is a known Go/Fyne limitation.
	a.textArea.SetText("")
	a.window.Clipboard().SetContent("")
}

// startAutoLock runs a background goroutine that locks the vault after
// autoLockDuration of inactivity.
func (a *NboxApp) startAutoLock() {
	a.touchActivity()
	go func() {
		ticker := time.NewTicker(autoLockCheckInterval)
		defer ticker.Stop()
		for range ticker.C {
			a.vaultMu.RLock()
			unlocked := a.vaultUnlocked
			a.vaultMu.RUnlock()
			if !unlocked {
				continue
			}
			last := time.Unix(0, a.lastActivity.Load())
			if time.Since(last) >= autoLockDuration {
				fyne.Do(func() {
					a.lockVault()
					a.statusLabel.SetText("Vault locked (inactivity)")
					dialog.ShowInformation("",
						fmt.Sprintf("Vault locked after %s of inactivity", autoLockDuration),
						a.window)
				})
			}
		}
	}()
}

// GUI helpers
func (a *NboxApp) clearText() {
	a.touchActivity()
	a.textArea.SetText("")
	a.window.Clipboard().SetContent("")
	a.statusLabel.SetText("Text and clipboard cleared")
}

func (a *NboxApp) toggleTheme() {
	if a.isDarkTheme {
		a.app.Settings().SetTheme(&orangeTheme{base: theme.LightTheme()})
		a.isDarkTheme = false
		a.themeSwitch.SetText("🌙")
	} else {
		a.app.Settings().SetTheme(&orangeTheme{base: theme.DarkTheme()})
		a.isDarkTheme = true
		a.themeSwitch.SetText("☀️")
	}
}

func (a *NboxApp) showInfoPopup() {
	projURL, _ := url.Parse("https://github.com/Ch1ffr3punk/Nbox")
	projectLink := widget.NewHyperlink("An Open Source project", projURL)
	okButton := widget.NewButton("OK", func() {
		if overlays := a.window.Canvas().Overlays(); overlays.Top() != nil {
			overlays.Remove(overlays.Top())
		}
	})
	okButton.Importance = widget.HighImportance
	content := container.NewVBox(
		widget.NewLabelWithStyle("Nbox v0.1.0", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),
		container.NewHBox(layout.NewSpacer(), projectLink, layout.NewSpacer()),
		widget.NewLabelWithStyle("released under the Apache 2.0 license", fyne.TextAlignCenter, fyne.TextStyle{}),
		widget.NewLabelWithStyle("© 2026 Ch1ffr3punk", fyne.TextAlignCenter, fyne.TextStyle{}),
		container.NewHBox(layout.NewSpacer(), okButton, layout.NewSpacer()),
	)
	dialog.ShowCustomWithoutButtons("", content, a.window)
}

// Init / Add
func (a *NboxApp) cmdInit() {
	a.ensureVaultUnlocked(func() {
		dialog.ShowEntryDialog("Enter identity name", "self", func(name string) {
			if name == "" {
				return
			}
			if !nameRegex.MatchString(name) {
				dialog.ShowError(fmt.Errorf("invalid name: %s", name), a.window)
				return
			}
			if a.getEntity(name) != nil {
				dialog.ShowError(fmt.Errorf("identity '%s' already exists", name), a.window)
				return
			}

			pub, sec, err := box.GenerateKey(rand.Reader)
			if err != nil {
				dialog.ShowError(err, a.window)
				return
			}
			var pemBuf strings.Builder
			for _, b := range []*pem.Block{
				{Type: "NaClbox SECRET KEY", Bytes: sec[:]},
				{Type: "NaClbox PUBLIC KEY", Bytes: pub[:]},
			} {
				if err := pem.Encode(&pemBuf, b); err != nil {
					dialog.ShowError(err, a.window)
					return
				}
			}
			a.putEntity(name, []byte(pemBuf.String()))
			a.persistVault()
			a.touchActivity()

			pubPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "NaClbox PUBLIC KEY",
				Bytes: pub[:],
			})
			pemEntry := widget.NewMultiLineEntry()
			pemEntry.SetText(string(pubPEM))
			pemEntry.Wrapping = fyne.TextWrapOff
			pemEntry.TextStyle = fyne.TextStyle{Monospace: true}
			pemScroll := container.NewScroll(pemEntry)
			pemScroll.SetMinSize(fyne.NewSize(480, 140))

			copyBtn := widget.NewButton("Copy to Clipboard", func() {
				a.secureCopy(string(pubPEM))
				a.statusLabel.SetText(fmt.Sprintf("Public key copied (auto-clears in %s)", clipboardClearDelay))
			})
			copyBtn.Importance = widget.HighImportance
			okBtn := widget.NewButton("OK", func() {
				for _, o := range a.window.Canvas().Overlays().List() {
					a.window.Canvas().Overlays().Remove(o)
				}
			})
			dialogContent := container.NewVBox(
				widget.NewLabelWithStyle(
					fmt.Sprintf("Identity '%s' created successfully", name),
					fyne.TextAlignCenter,
					fyne.TextStyle{Bold: true},
				),
				widget.NewSeparator(),
				widget.NewLabelWithStyle(
					"Share this public key with your peers:",
					fyne.TextAlignCenter,
					fyne.TextStyle{},
				),
				pemScroll,
				container.NewHBox(
					layout.NewSpacer(),
					copyBtn,
					layout.NewSpacer(),
					okBtn,
					layout.NewSpacer(),
				),
			)
			popup := widget.NewModalPopUp(dialogContent, a.window.Canvas())
			popup.Resize(fyne.NewSize(540, 320))
			popup.Show()
			a.statusLabel.SetText(fmt.Sprintf("Identity '%s' created", name))
		}, a.window)
	})
}

func (a *NboxApp) cmdAdd() {
	a.ensureVaultUnlocked(func() {
		nameEntry := widget.NewEntry()
		nameEntry.SetPlaceHolder("peer name")
		loadKeyBtn := widget.NewButton("Load Public Key (.pem)", func() {
			dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
				if reader == nil {
					return
				}
				defer reader.Close()
				data, err := io.ReadAll(reader)
				if err != nil {
					dialog.ShowError(err, a.window)
					return
				}
				block, _ := pem.Decode(data)
				if block == nil {
					dialog.ShowError(fmt.Errorf("no PEM block found in file"), a.window)
					return
				}
				if block.Type != "NaClbox PUBLIC KEY" {
					dialog.ShowError(fmt.Errorf("unexpected PEM block type: %q", block.Type), a.window)
					return
				}
				if len(block.Bytes) != 32 {
					dialog.ShowError(fmt.Errorf("invalid public key length: %d", len(block.Bytes)), a.window)
					return
				}
				var key [32]byte
				copy(key[:], block.Bytes)
				a.scannedPubKey = hex.EncodeToString(key[:])
				if nameEntry.Text == "" {
					base := filepath.Base(reader.URI().Path())
					base = strings.TrimSuffix(base, ".pub.pem")
					base = strings.TrimSuffix(base, ".pem")
					if base != "" {
						nameEntry.SetText(base)
					} else {
						nameEntry.SetText("peer_" + a.scannedPubKey[:8])
					}
				}
				a.touchActivity()
				a.statusLabel.SetText("Public key loaded")
				dialog.ShowInformation("Success", "Public key loaded.", a.window)
			}, a.window)
		})
		loadKeyBtn.Importance = widget.HighImportance
		items := []*widget.FormItem{
			{Text: "Name", Widget: nameEntry},
			{Text: "Load Key", Widget: loadKeyBtn},
		}
		dialog.ShowForm("Add Peer", "Add", "Cancel", items, func(confirmed bool) {
			if !confirmed {
				return
			}
			name := strings.TrimSpace(nameEntry.Text)
			if name == "" || !nameRegex.MatchString(name) {
				dialog.ShowError(fmt.Errorf("invalid name"), a.window)
				return
			}
			if a.scannedPubKey == "" {
				dialog.ShowError(fmt.Errorf("no public key loaded"), a.window)
				return
			}
			if a.getEntity(name) != nil {
				dialog.ShowError(fmt.Errorf("'%s' already exists", name), a.window)
				return
			}
			key, err := hex.DecodeString(a.scannedPubKey)
			if err != nil || len(key) != 32 {
				dialog.ShowError(fmt.Errorf("invalid public key"), a.window)
				return
			}
			var pemBuf strings.Builder
			if err := pem.Encode(&pemBuf, &pem.Block{Type: "NaClbox PUBLIC KEY", Bytes: key}); err != nil {
				dialog.ShowError(err, a.window)
				return
			}
			a.putEntity(name, []byte(pemBuf.String()))
			a.persistVault()
			a.touchActivity()
			a.scannedPubKey = ""
			a.statusLabel.SetText(fmt.Sprintf("Peer '%s' added", name))
		}, a.window)
	})
}

// Import / Export
func (a *NboxApp) cmdImportIdentity() {
	a.ensureVaultUnlocked(func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if reader == nil {
				return
			}
			defer reader.Close()
			data, err := io.ReadAll(reader)
			if err != nil {
				dialog.ShowError(err, a.window)
				return
			}
			var sec, pub *[32]byte
			rest := data
			for {
				block, remainder := pem.Decode(rest)
				if block == nil {
					break
				}
				switch block.Type {
				case "NaClbox SECRET KEY":
					sec = new([32]byte)
					copy(sec[:], block.Bytes)
				case "NaClbox PUBLIC KEY":
					pub = new([32]byte)
					copy(pub[:], block.Bytes)
				}
				rest = remainder
			}
			if sec == nil || pub == nil {
				dialog.ShowError(fmt.Errorf("identity file must contain both SECRET and PUBLIC key blocks"), a.window)
				return
			}
			dialog.ShowEntryDialog("Enter name for imported identity", "imported", func(name string) {
				if name == "" || !nameRegex.MatchString(name) {
					dialog.ShowError(fmt.Errorf("invalid name"), a.window)
					return
				}
				if a.getEntity(name) != nil {
					dialog.ShowError(fmt.Errorf("'%s' already exists", name), a.window)
					return
				}
				var pemBuf strings.Builder
				for _, b := range []*pem.Block{
					{Type: "NaClbox SECRET KEY", Bytes: sec[:]},
					{Type: "NaClbox PUBLIC KEY", Bytes: pub[:]},
				} {
					pem.Encode(&pemBuf, b)
				}
				a.putEntity(name, []byte(pemBuf.String()))
				a.persistVault()
				a.touchActivity()
				a.statusLabel.SetText(fmt.Sprintf("Identity '%s' imported", name))
			}, a.window)
		}, a.window)
	})
}

func (a *NboxApp) cmdExportIdentity() {
	a.ensureVaultUnlocked(func() {
		identities := a.listIdentities()
		if len(identities) == 0 {
			dialog.ShowError(fmt.Errorf("no identities to export"), a.window)
			return
		}
		identitySelect := widget.NewSelect(identities, func(selected string) {})
		identitySelect.SetSelected(identities[0])
		items := []*widget.FormItem{
			{Text: "Identity", Widget: identitySelect},
		}
		dialog.ShowForm("Export Identity", "Export", "Cancel", items, func(confirmed bool) {
			if !confirmed {
				return
			}
			selected := identitySelect.Selected
			if selected == "" {
				return
			}
			ent := a.getEntity(selected)
			if ent == nil || !ent.isIdentity() {
				dialog.ShowError(fmt.Errorf("invalid identity"), a.window)
				return
			}
			var pemBuf strings.Builder
			for _, b := range []*pem.Block{
				{Type: "NaClbox SECRET KEY", Bytes: ent.sec[:]},
				{Type: "NaClbox PUBLIC KEY", Bytes: ent.pub[:]},
			} {
				pem.Encode(&pemBuf, b)
			}
			dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
				if writer == nil {
					return
				}
				defer writer.Close()
				if _, err := writer.Write([]byte(pemBuf.String())); err != nil {
					dialog.ShowError(err, a.window)
					return
				}
				a.touchActivity()
				a.statusLabel.SetText(fmt.Sprintf("Identity '%s' exported", selected))
			}, a.window)
		}, a.window)
	})
}

// Delete
func (a *NboxApp) cmdDelete() {
	a.ensureVaultUnlocked(func() {
		identities := a.listIdentities()
		peers := a.listPeers()
		all := append([]string{}, identities...)
		all = append(all, peers...)
		if len(all) == 0 {
			dialog.ShowInformation("", "No keys to delete", a.window)
			return
		}
		keySelect := widget.NewSelect(all, func(selected string) {})
		keySelect.SetSelected(all[0])
		items := []*widget.FormItem{
			{Text: "Key", Widget: keySelect},
		}
		dialog.ShowForm("Delete Key", "Delete", "Cancel", items, func(confirmed bool) {
			if !confirmed {
				return
			}
			selected := keySelect.Selected
			if selected == "" {
				return
			}
			dialog.ShowConfirm("Confirm Delete",
				fmt.Sprintf("Really delete '%s'?", selected),
				func(yes bool) {
					if !yes {
						return
					}
					a.deleteEntity(selected)
					a.persistVault()
					a.touchActivity()
					a.statusLabel.SetText(fmt.Sprintf("'%s' deleted", selected))
				}, a.window)
		}, a.window)
	})
}

// Pad / Unpad
func (a *NboxApp) cmdPad() {
	text := a.textArea.GetText()
	if text == "" {
		dialog.ShowError(fmt.Errorf("no text to pad"), a.window)
		return
	}
	raw := []byte(text)
	padded := addISOPadding(raw, paddingBlockSize)
	if len(padded) == len(raw) {
		dialog.ShowInformation("", fmt.Sprintf("Already a multiple of %d bytes", paddingBlockSize), a.window)
		return
	}
	a.textArea.SetText(armorBase64(padded))
	a.touchActivity()
	a.statusLabel.SetText("Padded")
}

func (a *NboxApp) cmdUnpad() {
	text := a.textArea.GetText()
	if text == "" {
		dialog.ShowError(fmt.Errorf("no text to unpad"), a.window)
		return
	}
	padded, err := dearmorBase64(text)
	if err != nil {
		dialog.ShowError(fmt.Errorf("not valid Base64: %w", err), a.window)
		return
	}
	unpadded := removeISOPadding(padded, paddingBlockSize)
	if len(unpadded) == len(padded) {
		dialog.ShowInformation("", "No padding detected", a.window)
		return
	}
	a.textArea.SetText(string(unpadded))
	a.touchActivity()
	a.statusLabel.SetText("Unpadded")
}

// Encrypt / Decrypt
func (a *NboxApp) cmdEncrypt() {
	a.ensureVaultUnlocked(func() {
		text := a.textArea.GetText()
		if strings.TrimSpace(text) == "" {
			dialog.ShowError(fmt.Errorf("no text to encrypt"), a.window)
			return
		}
		identities := a.listIdentities()
		if len(identities) == 0 {
			dialog.ShowError(fmt.Errorf("no identities found. Create one with Init"), a.window)
			return
		}
		peers := a.listPeers()
		if len(peers) == 0 {
			dialog.ShowError(fmt.Errorf("no peers found. Add one with Add"), a.window)
			return
		}
		senderSelect := widget.NewSelect(identities, func(selected string) {})
		senderSelect.SetSelected(identities[0])
		recipientSelect := widget.NewSelect(peers, func(selected string) {})
		recipientSelect.SetSelected(peers[0])
		items := []*widget.FormItem{
			{Text: "Your Identity", Widget: senderSelect},
			{Text: "Recipient", Widget: recipientSelect},
		}
		dialog.ShowForm("Encrypt", "Encrypt", "Cancel", items, func(confirmed bool) {
			if !confirmed {
				return
			}
			from := senderSelect.Selected
			to := recipientSelect.Selected
			sender := a.getEntity(from)
			if sender == nil || sender.sec == nil {
				dialog.ShowError(fmt.Errorf("invalid sender identity"), a.window)
				return
			}
			recv := a.getEntity(to)
			if recv == nil || recv.pub == nil {
				dialog.ShowError(fmt.Errorf("invalid recipient public key"), a.window)
				return
			}
			msgBuf := memguard.NewBufferFromBytes([]byte(text))
			defer msgBuf.Destroy()

			var nonce [24]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				dialog.ShowError(err, a.window)
				return
			}
			encrypted := box.Seal(nil, msgBuf.Bytes(), &nonce, recv.pub, sender.sec)
			ciphertext := append(nonce[:], encrypted...)
			a.textArea.SetText(armorBase64(ciphertext))
			a.touchActivity()
			a.statusLabel.SetText(fmt.Sprintf("Encrypted for '%s' (as '%s')", to, from))
		}, a.window)
	})
}

func (a *NboxApp) cmdDecrypt() {
	a.ensureVaultUnlocked(func() {
		raw := strings.TrimSpace(a.textArea.GetText())
		if raw == "" {
			dialog.ShowError(fmt.Errorf("no ciphertext in text area"), a.window)
			return
		}
		identities := a.listIdentities()
		if len(identities) == 0 {
			dialog.ShowError(fmt.Errorf("no identities found"), a.window)
			return
		}
		peers := a.listPeers()
		ciphertext, err := dearmorBase64(raw)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid Base64: %w", err), a.window)
			return
		}
		if len(ciphertext) < 24 {
			dialog.ShowError(fmt.Errorf("ciphertext too short"), a.window)
			return
		}
		var nonce [24]byte
		copy(nonce[:24], ciphertext[:24])
		encrypted := ciphertext[24:]

		var decryptedMsg []byte
		found := false
	OuterLoop:
		for _, identityName := range identities {
			myIdentity := a.getEntity(identityName)
			if myIdentity == nil || myIdentity.sec == nil {
				continue
			}
			for _, peerName := range peers {
				senderPeer := a.getEntity(peerName)
				if senderPeer == nil || senderPeer.pub == nil {
					continue
				}
				msg, ok := box.Open(nil, encrypted, &nonce, senderPeer.pub, myIdentity.sec)
				if ok {
					decryptedMsg = msg
					found = true
					break OuterLoop
				}
			}
			if myIdentity.pub != nil {
				msg, ok := box.Open(nil, encrypted, &nonce, myIdentity.pub, myIdentity.sec)
				if ok {
					decryptedMsg = msg
					found = true
					break OuterLoop
				}
			}
		}
		if !found {
			dialog.ShowError(errors.New("decryption failed: Unknown key pair or corrupted message"), a.window)
			return
		}
		msgBuf := memguard.NewBufferFromBytes(decryptedMsg)
		defer msgBuf.Destroy()

		// NOTE: Converting to a Go string creates an immutable copy that
		// cannot be wiped. This is an unavoidable limitation when passing
		// data to Fyne widgets. The original buffer is destroyed via defer.
		if isPrintable(msgBuf.Bytes()) {
			a.textArea.SetText(string(msgBuf.Bytes()))
			a.touchActivity()
			a.statusLabel.SetText("Decryption successful")
		} else {
			a.textArea.SetText(armorBase64(msgBuf.Bytes()))
			a.touchActivity()
			a.statusLabel.SetText("Decryption successful (padded – click Unpad)")
		}
	})
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// GUI
func (a *NboxApp) setupUI() {
	a.textArea = NewScrollableEntry()
	a.textArea.SetPlaceHolder("Enter text or paste ciphertext here...")
	a.textArea.SetOnChanged(func(string) {
		a.touchActivity()
	})
	a.statusLabel = widget.NewLabel("Ready")
	statusBar := container.NewVBox(
		widget.NewSeparator(),
		container.NewHBox(a.statusLabel),
	)

	a.themeSwitch = widget.NewButton("☀️", a.toggleTheme)
	a.themeSwitch.Importance = widget.LowImportance
	a.infoBtn = widget.NewButtonWithIcon("", theme.InfoIcon(), a.showInfoPopup)
	a.infoBtn.Importance = widget.LowImportance
	a.clearBtn = widget.NewButtonWithIcon("", theme.ContentClearIcon(), a.clearText)
	a.clearBtn.Importance = widget.LowImportance
	a.deleteBtn = widget.NewButtonWithIcon("", theme.DeleteIcon(), a.cmdDelete)
	a.deleteBtn.Importance = widget.LowImportance
	a.importBtn = widget.NewButtonWithIcon("", theme.DownloadIcon(), a.cmdImportIdentity)
	a.importBtn.Importance = widget.LowImportance
	a.exportBtn = widget.NewButtonWithIcon("", theme.UploadIcon(), a.cmdExportIdentity)
	a.exportBtn.Importance = widget.LowImportance

	topBar := container.NewHBox(
		layout.NewSpacer(),
		a.infoBtn,
		a.importBtn,
		a.exportBtn,
		a.deleteBtn,
		a.clearBtn,
		layout.NewSpacer(),
		a.themeSwitch,
	)

	btnInit := widget.NewButton("Init", a.cmdInit)
	btnAdd := widget.NewButton("Add", a.cmdAdd)
	btnPad := widget.NewButton("Pad", a.cmdPad)
	btnEncrypt := widget.NewButton("Encrypt", a.cmdEncrypt)
	btnDecrypt := widget.NewButton("Decrypt", a.cmdDecrypt)
	btnUnpad := widget.NewButton("Unpad", a.cmdUnpad)
	for _, btn := range []*widget.Button{btnInit, btnAdd, btnPad, btnEncrypt, btnDecrypt, btnUnpad} {
		btn.Importance = widget.HighImportance
	}

	row1 := container.New(layout.NewGridLayoutWithColumns(3), btnInit, btnAdd, btnPad)
	row2 := container.New(layout.NewGridLayoutWithColumns(3), btnEncrypt, btnDecrypt, btnUnpad)
	buttonContainer := container.NewVBox(row1, row2)

	scrollArea := container.NewScroll(a.textArea)
	scrollArea.SetMinSize(fyne.NewSize(400, 200))

	content := container.NewBorder(
		container.NewVBox(topBar, widget.NewSeparator(), buttonContainer),
		statusBar,
		nil,
		nil,
		scrollArea,
	)
	a.window.SetContent(content)
}

// Main
func main() {
	defer memguard.Purge()
	memguard.CatchInterrupt()

	myApp := app.NewWithID("oc2mx.net.nbox")
	myApp.Settings().SetTheme(&orangeTheme{base: theme.DarkTheme()})
	window := myApp.NewWindow("Nbox")
	window.Resize(fyne.NewSize(800, 600))
	window.CenterOnScreen()

	appState := &NboxApp{
		app:          myApp,
		window:       window,
		isDarkTheme:  true,
		vaultEntries: map[string][]byte{},
	}
	appState.setupUI()
	appState.startAutoLock()

	// On startup, if a vault file exists, restore the persisted lockout
	// counter and then prompt for the passphrase.
	go func() {
		time.Sleep(500 * time.Millisecond)
		if vaultExists() {
			if attempts, lastAttempt, err := loadVaultLockout(); err == nil {
				appState.decryptAttempts = int(attempts)
				appState.lastAttempt = time.Unix(lastAttempt, 0)
			}
			fyne.Do(func() {
				appState.ensureVaultUnlocked(func() {})
			})
		}
	}()

	window.SetCloseIntercept(func() {
		appState.persistVault()
		appState.lockVault()
		memguard.Purge()
		window.Close()
	})
	window.ShowAndRun()
}
