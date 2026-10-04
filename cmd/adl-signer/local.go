package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/edge-labs/adl-signing-server/internal/auth"
	"github.com/edge-labs/adl-signing-server/internal/localstack"
	"github.com/edge-labs/adl-signing-server/internal/pki"
)

// runLocal starts an in-memory server for trying the CLI or firmware
// integration without AWS. Every caller gets every permission; the
// X-Adl-Local-Principal header just names them in the audit log.
func runLocal(listen string) error {
	if listen == "" {
		listen = "127.0.0.1:8080"
	}
	if err := requireLoopback(listen); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	st, err := localstack.New(log)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "adl-local-ca-")
	if err != nil {
		return err
	}
	for env, root := range st.Roots {
		p := filepath.Join(dir, env+"-root.pem")
		if err := os.WriteFile(p, pki.EncodeCertificates(root), 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, `
  LOCAL INSECURE MODE - throwaway CA, in-memory storage, no authentication.
  Never flash these certificates onto anything you care about.

  Local roots written to %s
  Point the CLI at it with:  adl configure --url http://%s --local
`+"\n", dir, listen)
	return serve(listen, st.Handler(&auth.Local{Permissions: []string{"*"}}, log), log)
}
