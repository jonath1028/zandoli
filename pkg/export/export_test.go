package export_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"zandoli/pkg/export"
	"zandoli/pkg/sniffer"
)

func TestExportAll_WithOneHost(t *testing.T) {
	tmpDir := createTempDir(t)
	defer os.RemoveAll(tmpDir)

	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	ip := net.ParseIP("192.168.1.10")
	host := sniffer.Host{
		IP:     ip,
		MAC:    mac,
		Vendor: "UnitTestVendor",
	}
	hosts := []sniffer.Host{host}

	if err := export.ExportAll(hosts, tmpDir); err != nil {
		t.Fatalf("ExportAll failed with 1 host: %v", err)
	}

	checkExportedFiles(t, tmpDir)
}

func TestExportAll_WithEmptyList(t *testing.T) {
	tmpDir := createTempDir(t)
	defer os.RemoveAll(tmpDir)

	var hosts []sniffer.Host

	if err := export.ExportAll(hosts, tmpDir); err != nil {
		t.Fatalf("ExportAll failed with empty list: %v", err)
	}

	checkExportedFiles(t, tmpDir)
}

func TestExportAll_WithInvalidPath(t *testing.T) {
	// Crée un fichier à la place d’un dossier
	conflictPath := createTempFile(t)
	defer os.Remove(conflictPath)

	mac, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	ip := net.ParseIP("10.0.0.1")
	hosts := []sniffer.Host{{IP: ip, MAC: mac}}

	err := export.ExportAll(hosts, conflictPath)
	if err == nil {
		t.Errorf("Expected error when output path is a file, got nil")
	}
}

func createTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "zandoli-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}

func createTempFile(t *testing.T) string {
	f, err := os.CreateTemp("", "zandoli-conflict")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func checkExportedFiles(t *testing.T, dir string) {
	// On vérifie uniquement que les fichiers attendus existent, peu importe le timestamp
	files := []string{}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, filepath.Base(path))
		}
		return nil
	})

	expected := []string{".json", ".csv", ".html"}
	for _, ext := range expected {
		found := false
		for _, f := range files {
			if filepath.Ext(f) == ext {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing exported file with extension %s", ext)
		}
	}
}

