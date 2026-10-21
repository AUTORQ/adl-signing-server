// Package cliinstall gives a Cobra binary an `install` command that puts the
// binary on PATH and its shell completion where the shell loads it on demand.
//
//	adl install                    binary + completion for this user
//	sudo adl install system        machine-wide (same as --system)
//	adl install cli local          just the binary, for this user
//	adl install completion system  just the completion, machine-wide
//	adl install cli --bin-dir ~/bin
//	adl install completion --shell zsh
//
// Every name (binary, completion file) comes from the root command, so the
// same code serves adl and adl-signer.
package cliinstall

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// target is the pair of directories an install writes into. "local" is the
// per-user layout (~/.local), "system" the machine-wide one (/usr/local).
// Either path can be overridden on the command line.
type target struct {
	local, system bool
	binDir        string
	completionDir string
	shell         string
}

const (
	localBinDir  = "~/.local/bin"
	systemBinDir = "/usr/local/bin"
)

// shellDirs are where each shell finds a completion file without any further
// setup, per user and per machine.
type shellDirs struct{ local, system string }

var completionDirs = map[string]shellDirs{
	"bash": {"~/.local/share/bash-completion/completions", "/usr/share/bash-completion/completions"},
	"zsh":  {"~/.local/share/zsh/site-functions", "/usr/local/share/zsh/site-functions"},
	"fish": {"~/.config/fish/completions", "/usr/share/fish/vendor_completions.d"},
}

// completionFile is the file name each shell looks for when it completes
// the command `name`.
func completionFile(shell, name string) string {
	switch shell {
	case "zsh":
		return "_" + name
	case "fish":
		return name + ".fish"
	}
	return name
}

func (t *target) bind(cmd *cobra.Command, withBin, withCompletion bool) {
	f := cmd.Flags()
	f.BoolVar(&t.local, "local", false, "Install for this user under ~/.local (the default)")
	f.BoolVar(&t.system, "system", false, "Install machine-wide under /usr/local and /usr/share (usually needs sudo)")
	cmd.MarkFlagsMutuallyExclusive("local", "system")
	if withBin {
		f.StringVar(&t.binDir, "bin-dir", "", "Directory to install the binary into (default "+localBinDir+" or "+systemBinDir+")")
		_ = cmd.RegisterFlagCompletionFunc("bin-dir", completeDirs)
	}
	if withCompletion {
		f.StringVar(&t.completionDir, "completion-dir", "", "Directory to install the completion file into (default depends on --shell and --local/--system)")
		f.StringVar(&t.shell, "shell", "", "Shell to install completion for: bash, zsh or fish (default: from $SHELL, else bash)")
		_ = cmd.RegisterFlagCompletionFunc("completion-dir", completeDirs)
		_ = cmd.RegisterFlagCompletionFunc("shell", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return []string{"bash", "zsh", "fish"}, cobra.ShellCompDirectiveNoFileComp
		})
	}
}

// scopes are the positional spellings of --local and --system.
var scopes = []string{"local", "system"}

// applyScope folds an optional "local" or "system" argument into the flags,
// refusing a word that contradicts a flag.
func (t *target) applyScope(args []string) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "local":
		if t.system {
			return fmt.Errorf("\"local\" contradicts --system")
		}
		t.local = true
	case "system":
		if t.local {
			return fmt.Errorf("\"system\" contradicts --local")
		}
		t.system = true
	default:
		return fmt.Errorf("unknown scope %q: expected local or system", args[0])
	}
	return nil
}

var scopeArgs = cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs)

func completeDirs(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveFilterDirs
}

func (t *target) resolveBinDir() (string, error) {
	if t.binDir != "" {
		return expandHome(t.binDir)
	}
	if t.system {
		return systemBinDir, nil
	}
	return expandHome(localBinDir)
}

func (t *target) resolveShell() (string, error) {
	shell := t.shell
	if shell == "" {
		shell = filepath.Base(os.Getenv("SHELL"))
	}
	switch shell {
	case "bash", "zsh", "fish":
		return shell, nil
	case "", ".":
		return "bash", nil
	}
	if t.shell != "" {
		return "", fmt.Errorf("unsupported --shell %q: expected bash, zsh or fish", t.shell)
	}
	// An unusual $SHELL is not an error; bash is the safe guess.
	return "bash", nil
}

func (t *target) resolveCompletion(name string) (shell, dir, file string, err error) {
	shell, err = t.resolveShell()
	if err != nil {
		return "", "", "", err
	}
	dirs := completionDirs[shell]
	dir = t.completionDir
	if dir == "" {
		dir = dirs.local
		if t.system {
			dir = dirs.system
		}
	}
	dir, err = expandHome(dir)
	return shell, dir, completionFile(shell, name), err
}

func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot resolve ~: %w", err)
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
	}
	return path, nil
}

// New returns the install command. Add it to the root command; it reads the
// binary's name from there when it runs.
func New() *cobra.Command {
	var all target
	cmd := &cobra.Command{
		Use:   "install [local|system]",
		Short: "Install this binary and its shell completion",
		Long: `Install this binary and its completion script where your shell will find them.

With no subcommand both are installed; "install cli" and "install completion" do one
half each. Every form takes the scope as a word or a flag: "local" / --local (the
default) is a per-user install and "system" / --system a machine-wide one:

              --local                                       --system
  binary      ~/.local/bin/NAME                             /usr/local/bin/NAME
  bash        ~/.local/share/bash-completion/completions/   /usr/share/bash-completion/completions/
  zsh         ~/.local/share/zsh/site-functions/_NAME       /usr/local/share/zsh/site-functions/_NAME
  fish        ~/.config/fish/completions/NAME.fish          /usr/share/fish/vendor_completions.d/NAME.fish

--bin-dir and --completion-dir override either path. The shell comes from --shell, then
$SHELL, then bash.`,
		Example: `  NAME install                         # binary + completion for this user
  sudo NAME install system             # both, machine-wide
  NAME install cli local               # binary only, ~/.local/bin
  sudo NAME install cli system         # binary only, /usr/local/bin
  NAME install completion local        # completion only, for this user
  sudo NAME install completion system  # completion only, machine-wide
  NAME install cli --bin-dir ~/bin
  NAME install completion --shell zsh`,
		Args:      scopeArgs,
		ValidArgs: scopes,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := all.applyScope(args); err != nil {
				return err
			}
			if err := installCLI(cmd, &all); err != nil {
				return err
			}
			return installCompletion(cmd, &all)
		},
	}
	all.bind(cmd, true, true)

	var cli target
	cliCmd := &cobra.Command{
		Use:       "cli [local|system]",
		Short:     "Copy this binary into a directory on PATH",
		Example:   "  NAME install cli local\n  sudo NAME install cli system",
		Args:      scopeArgs,
		ValidArgs: scopes,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cli.applyScope(args); err != nil {
				return err
			}
			return installCLI(cmd, &cli)
		},
	}
	cli.bind(cliCmd, true, false)

	var comp target
	compCmd := &cobra.Command{
		Use:       "completion [local|system]",
		Short:     "Write the completion script where the shell loads it from",
		Example:   "  NAME install completion local\n  sudo NAME install completion system --shell zsh",
		Args:      scopeArgs,
		ValidArgs: scopes,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := comp.applyScope(args); err != nil {
				return err
			}
			return installCompletion(cmd, &comp)
		},
	}
	comp.bind(compCmd, false, true)

	cmd.AddCommand(cliCmd, compCmd)
	return cmd
}

// fixExamples swaps the NAME placeholder for the real binary name once the
// command is attached to a root.
func fixExamples(cmd *cobra.Command) {
	name := cmd.Root().Name()
	cmd.Long = strings.ReplaceAll(cmd.Long, "NAME", name)
	cmd.Example = strings.ReplaceAll(cmd.Example, "NAME", name)
	for _, c := range cmd.Commands() {
		fixExamples(c)
	}
}

// Attach adds the install command to root with the help text filled in.
func Attach(root *cobra.Command) *cobra.Command {
	cmd := New()
	root.AddCommand(cmd)
	fixExamples(cmd)
	return cmd
}

// installCLI copies the running executable into the bin directory. It writes
// a temp file and renames it, so a binary already on PATH is replaced
// atomically, and a running copy keeps its own inode instead of being
// overwritten underneath itself.
func installCLI(cmd *cobra.Command, t *target) error {
	w := cmd.OutOrStdout()
	name := cmd.Root().Name()
	dir, err := t.resolveBinDir()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate this binary: %w", err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return fmt.Errorf("cannot resolve this binary: %w", err)
	}

	dest := filepath.Join(dir, name)
	if same, _ := sameFile(self, dest); same {
		fmt.Fprintf(w, "ok %s is already this binary\n", dest)
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := copyFile(self, dest, 0o755); err != nil {
		return err
	}
	fmt.Fprintf(w, "ok installed %s\n", dest)
	if !onPath(dir) {
		fmt.Fprintf(w, "note: %s is not on PATH; completion needs the binary reachable by name\n", dir)
	}
	return nil
}

// installCompletion generates the script for the chosen shell straight into
// its file, so it always matches the binary being installed rather than
// whatever older copy is on PATH.
func installCompletion(cmd *cobra.Command, t *target) error {
	w := cmd.OutOrStdout()
	root := cmd.Root()
	shell, dir, file, err := t.resolveCompletion(root.Name())
	if err != nil {
		return err
	}

	var script bytes.Buffer
	switch shell {
	case "bash":
		err = root.GenBashCompletionV2(&script, true)
	case "zsh":
		err = root.GenZshCompletion(&script)
	case "fish":
		err = root.GenFishCompletion(&script, true)
	}
	if err != nil {
		return fmt.Errorf("generating %s completion: %w", shell, err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	dest := filepath.Join(dir, file)
	if err := writeFileAtomic(dest, script.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "ok installed %s completion at %s\n", shell, dest)

	switch shell {
	case "bash":
		fmt.Fprintf(w, "hint: bash-completion loads it on demand; open a new shell, or: source %s\n", dest)
	case "zsh":
		fmt.Fprintf(w, "hint: make sure %s is in $fpath before compinit runs, then open a new shell\n", dir)
	case "fish":
		fmt.Fprintf(w, "hint: fish picks it up on the next shell\n")
	}
	return nil
}

func copyFile(src, dest string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	return writeFileAtomic(dest, data, mode)
}

// writeFileAtomic writes next to the destination and renames over it, so a
// reader never sees a half-written file and a running binary is never
// truncated under itself.
func writeFileAtomic(dest string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("installing %s: %w", dest, err)
	}
	return nil
}

func sameFile(a, b string) (bool, error) {
	ia, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ia, ib), nil
}

func onPath(dir string) bool {
	clean := filepath.Clean(dir)
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p != "" && filepath.Clean(p) == clean {
			return true
		}
	}
	return false
}
