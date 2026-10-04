// Package version is stamped at build time via -ldflags.
package version

var (
	Version = "dev"
	Commit  = "unknown"
)

func String() string { return Version + " (" + Commit + ")" }
