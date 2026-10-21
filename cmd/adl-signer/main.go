// Command adl-signer is the signing server. The same binary runs as:
//
//   - an AWS Lambda function behind API Gateway (detected automatically),
//   - a long running HTTP service on EC2 (adl-signer serve),
//   - a throwaway local instance for trying things out (adl-signer serve --local-insecure).
package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"

	"github.com/AUTORQ/adl-signing-server/internal/api"
	"github.com/AUTORQ/adl-signing-server/internal/archive"
	"github.com/AUTORQ/adl-signing-server/internal/auth"
	"github.com/AUTORQ/adl-signing-server/internal/cliinstall"
	"github.com/AUTORQ/adl-signing-server/internal/config"
	"github.com/AUTORQ/adl-signing-server/internal/kmssigner"
	"github.com/AUTORQ/adl-signing-server/internal/lambdahttp"
	"github.com/AUTORQ/adl-signing-server/internal/service"
	"github.com/AUTORQ/adl-signing-server/internal/store"
	"github.com/AUTORQ/adl-signing-server/internal/version"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "adl-signer:", err)
		os.Exit(1)
	}
}

// serveOptions are the serve flags. The root command runs serve with the
// zero value, which is what Lambda does: it starts the binary with no
// arguments.
type serveOptions struct {
	localInsecure bool
	listen        string
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "adl-signer",
		Short: "The ADL signing server",
		Long: `adl-signer is the ADL signing server. With no arguments it serves: as a Lambda
function when AWS_LAMBDA_RUNTIME_API is set, otherwise as an HTTP service on
$ADL_LISTEN_ADDR. Configuration comes from ADL_* environment variables; see
docs/operations.md.`,
		Example: `  adl-signer serve                     # EC2 / systemd
  adl-signer serve --local-insecure    # throwaway local server, no AWS
  adl-signer install                   # put it on PATH with completion`,
		Version:       version.String(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			return runServe(serveOptions{})
		},
	}

	var o serveOptions
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run the server (Lambda is detected automatically)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runServe(o)
		},
	}
	serve.Flags().BoolVar(&o.localInsecure, "local-insecure", false, "run with in-memory storage, a throwaway CA and no real authentication (loopback only)")
	serve.Flags().StringVar(&o.listen, "listen", "", "listen address (default $ADL_LISTEN_ADDR or 127.0.0.1:8080)")
	_ = serve.RegisterFlagCompletionFunc("listen", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"127.0.0.1:8080", "0.0.0.0:8080"}, cobra.ShellCompDirectiveNoFileComp
	})

	root.AddCommand(serve, &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
		},
	})
	cliinstall.Attach(root)
	return root
}

func runServe(o serveOptions) error {
	if o.localInsecure {
		return runLocal(o.listen)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	handler, err := buildAWS(context.Background(), cfg, log)
	if err != nil {
		return err
	}

	if os.Getenv("AWS_LAMBDA_RUNTIME_API") != "" {
		log.Info("starting in lambda mode", "version", version.String())
		lambda.Start(lambdahttp.Handler(handler))
		return nil
	}
	addr := cfg.ListenAddr
	if o.listen != "" {
		addr = o.listen
	}
	return serve(addr, handler, log)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func buildAWS(ctx context.Context, cfg *config.Server, log *slog.Logger) (http.Handler, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	kmsClient := kms.NewFromConfig(awsCfg)
	reg := store.NewDynamo(dynamodb.NewFromConfig(awsCfg), cfg.TableName)
	arc := archive.NewS3(s3.NewFromConfig(awsCfg), cfg.ArchiveBucket, cfg.DataKMSKeyID, cfg.EscrowKMSKeyID)

	factory := func(ctx context.Context, env string) (crypto.Signer, error) {
		keyID, ok := cfg.KMSKey(env)
		if !ok {
			return nil, fmt.Errorf("no kms key for env %s", env)
		}
		return kmssigner.New(ctx, kmsClient, keyID)
	}
	svc, err := service.New(service.Options{
		Store: reg, Archive: arc, CAs: service.NewCAs(factory, arc, nil),
		Envs: cfg.ServiceEnvs(), Organization: cfg.Organization, DeviceIDPattern: cfg.DeviceIDPattern, Log: log,
	})
	if err != nil {
		return nil, err
	}
	verifier := &auth.STSVerifier{
		Audience: cfg.AuthAudience, Regions: cfg.AuthSTSRegions, Policy: cfg.AuthPolicy,
		Nonces: reg, HTTP: &http.Client{Timeout: 10 * time.Second}, Log: log,
	}
	return api.New(svc, verifier, log), nil
}

func serve(addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr, "version", version.String())
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--local-insecure only listens on loopback, not %q", addr)
	}
	return nil
}
