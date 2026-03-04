// Package output handles writing enumeration results to disk.
package output

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Writer writes JSON output files.
type Writer struct {
	dir     string
	verbose bool
}

// NewWriter creates a Writer targeting the given directory.
func NewWriter(dir string, verbose bool) *Writer {
	return &Writer{dir: dir, verbose: verbose}
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

	path := filepath.Join(w.dir, name)
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Printf("[-] Write %s: %v", name, err)
		return
	}

	if w.verbose {
		log.Printf("[+] Wrote %s (%s)", path, humanSize(len(b)))
	}
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
