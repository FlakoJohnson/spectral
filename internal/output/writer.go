// Package output handles writing enumeration results to disk.
package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Writer writes JSON output files.
type Writer struct {
	dir       string
	verbose   bool
	obfuscate bool
	manifest  map[string]string // hash -> original name
}

// NewWriter creates a Writer targeting the given directory.
func NewWriter(dir string, verbose bool) *Writer {
	return &Writer{dir: dir, verbose: verbose, manifest: make(map[string]string)}
}

// SetObfuscate enables filename obfuscation for stealth mode.
func (w *Writer) SetObfuscate(on bool) {
	w.obfuscate = on
}

// Envelope wraps results with metadata for later analysis.
type Envelope struct {
	CollectedAt string      `json:"collected_at"`
	Count       int         `json:"count"`
	Data        interface{} `json:"data"`
}

// Write serialises data to <dir>/<name> as pretty JSON.
func (w *Writer) Write(name string, data interface{}) {
	env := Envelope{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Data:        data,
	}

	// Set count where possible.
	switch v := data.(type) {
	case []interface{}:
		env.Count = len(v)
	}

	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		log.Printf("[-] Marshal %s: %v", name, err)
		return
	}

	outName := name
	if w.obfuscate {
		h := sha256.Sum256([]byte(name))
		outName = fmt.Sprintf("%x.json", h[:6])
		w.manifest[outName] = name
		// Write manifest so operator can decode filenames
		w.writeManifest()
	}

	path := filepath.Join(w.dir, outName)
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Printf("[-] Write %s: %v", outName, err)
		return
	}

	if w.verbose {
		log.Printf("[+] Wrote %s (%s)", path, humanSize(len(b)))
	}
}

// writeManifest saves the hash->name mapping to a manifest file.
func (w *Writer) writeManifest() {
	b, _ := json.MarshalIndent(w.manifest, "", "  ")
	path := filepath.Join(w.dir, ".manifest.json")
	os.WriteFile(path, b, 0600)
}

func humanSize(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
