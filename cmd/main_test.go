package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()

	repoRoot := locateRepoRoot(t)
	tmp := t.TempDir()
	out := filepath.Join(tmp, "zandoli_test")

	cmd := exec.Command("go", "build", "-o", out, "./cmd")
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v\n%s", err, string(outBytes))
	}
	return out
}

func locateRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current dir: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

func TestMain_Help(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("Execution failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "--config") {
		t.Errorf("Expected help output to mention --config")
	}
}

func TestMain_ValidConfig(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--config=assets/config_test.yaml", "--mode=passive")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		t.Fatalf("Execution failed with valid config: %v", err)
	}
}

func TestMain_InvalidConfigFile(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--config=nonexistent.yaml")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Expected failure with nonexistent config file")
	}
}

func TestMain_InvalidScanMode(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--config=assets/config_test.yaml", "--mode=INVALID")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Expected failure with invalid scan mode")
	}
}

func TestMain_ModePCAP_FileMissing(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--config=assets/config_test.yaml", "--mode=pcap", "--pcap=/tmp/doesnotexist.pcap")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Expected failure with missing pcap file")
	}
}

func TestMain_ModeCombined(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--config=assets/config_test.yaml", "--mode=combined")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		t.Fatalf("Execution failed in combined mode: %v", err)
	}
}

func TestMain_UnwritableOutputDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Skipping permission test as root")
	}

	tmpConfig := filepath.Join(t.TempDir(), "config_bad.yaml")
	configContent := `
iface: lo
passive_duration: 1
log_level: debug
log_file: /dev/null
output_dir: /root/
scan:
  mode: passive
  active_type: ""
`
	if err := os.WriteFile(tmpConfig, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	bin := buildBinary(t)
	cmd := exec.Command(bin, "--config="+tmpConfig)
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Expected failure when output_dir is unwritable")
	}
}

