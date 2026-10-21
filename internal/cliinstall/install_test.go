package cliinstall_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/cliinstall"
)

func newRoot(name string) *cobra.Command {
	root := &cobra.Command{Use: name}
	root.AddCommand(&cobra.Command{Use: "hello", Run: func(*cobra.Command, []string) {}})
	cliinstall.Attach(root)
	return root
}

func run(t *testing.T, root *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestInstallBinaryAndCompletion(t *testing.T) {
	bin, comp := t.TempDir(), t.TempDir()
	out, err := run(t, newRoot("adltest"), "install", "--bin-dir", bin, "--completion-dir", comp, "--shell", "zsh")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := os.Stat(filepath.Join(bin, "adltest"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("binary not installed with 0755: %v %v", st, err)
	}
	script, err := os.ReadFile(filepath.Join(comp, "_adltest"))
	if err != nil || !strings.Contains(string(script), "#compdef adltest") {
		t.Fatalf("zsh completion missing or not for adltest: %v", err)
	}
}

func TestCompletionFileNamesPerShell(t *testing.T) {
	for shell, file := range map[string]string{"bash": "adltest", "zsh": "_adltest", "fish": "adltest.fish"} {
		dir := t.TempDir()
		if out, err := run(t, newRoot("adltest"), "install", "completion", "--shell", shell, "--completion-dir", dir); err != nil {
			t.Fatalf("%s: %v\n%s", shell, err, out)
		}
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Errorf("%s: expected %s: %v", shell, file, err)
		}
	}
}

func TestInstallReplacesByRenameNotInPlace(t *testing.T) {
	bin := t.TempDir()
	dest := filepath.Join(bin, "adltest")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(dest)
	// Hold the old file open the way a running process holds its binary.
	held, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if out, err := run(t, newRoot("adltest"), "install", "cli", "--bin-dir", bin); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	after, _ := os.Stat(dest)
	if os.SameFile(before, after) {
		t.Fatal("binary was overwritten in place; a running copy would be corrupted")
	}
	buf := make([]byte, 3)
	if _, err := held.ReadAt(buf, 0); err != nil || string(buf) != "old" {
		t.Errorf("old inode changed under its reader: %q %v", buf, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(bin, ".adltest.*"))
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

func TestLocalAndSystemAreExclusive(t *testing.T) {
	if _, err := run(t, newRoot("adltest"), "install", "--local", "--system"); err == nil {
		t.Fatal("--local and --system together should be refused")
	}
}

func TestScopeWordsMatchFlags(t *testing.T) {
	bin, comp := t.TempDir(), t.TempDir()
	for _, args := range [][]string{
		{"install", "cli", "local", "--bin-dir", bin},
		{"install", "completion", "local", "--completion-dir", comp, "--shell", "bash"},
		{"install", "local", "--bin-dir", bin, "--completion-dir", comp, "--shell", "bash"},
	} {
		if out, err := run(t, newRoot("adltest"), args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	for _, args := range [][]string{
		{"install", "cli", "system", "--local"},
		{"install", "completion", "local", "--system"},
		{"install", "cli", "everywhere"},
		{"install", "local", "system"},
	} {
		if _, err := run(t, newRoot("adltest"), args...); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
}

func TestScopeWordsComplete(t *testing.T) {
	out, err := run(t, newRoot("adltest"), "__complete", "install", "cli", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "local") || !strings.Contains(out, "system") {
		t.Errorf("install cli should complete local/system:\n%s", out)
	}
}

func TestBadShellRejected(t *testing.T) {
	if _, err := run(t, newRoot("adltest"), "install", "completion", "--shell", "tcsh", "--completion-dir", t.TempDir()); err == nil {
		t.Fatal("unsupported shell should be refused")
	}
}

func TestHelpUsesRootName(t *testing.T) {
	out, err := run(t, newRoot("adltest"), "install", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "NAME") || !strings.Contains(out, "adltest install system") {
		t.Errorf("help text not specialised to the binary:\n%s", out)
	}
}
