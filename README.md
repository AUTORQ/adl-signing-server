# adl-signing-server

Issues and tracks the X.509 identities of ADL devices (ESP32-S3), so that
nobody has to run openssl by hand or keep CA keys on a server's disk.

- Developers get a dev certificate with one command, and can get it back
  later if they lose it.
- The factory line provisions production boards at end of line. The key is
  generated on the station, written to the chip, never stored anywhere else,
  and recorded against the chip's MAC.
- The CA keys live in AWS KMS and cannot be exported. Only the service
  role can sign with them.
- Every certificate is archived in a versioned, Object Locked S3 bucket.
  A DynamoDB registry records who issued what, when and for which chip.
- It runs as a Lambda or on EC2, or both at once, from the same binary
  and the same Terraform.

```
 developer laptop          factory station                  CA admin
   adl mint / flash        adl eol provision                adl ca / revoke / audit
      |                          |  esptool + NVS image           |
      +------------+-------------+--------------------------------+
                   |  HTTPS, caller proves its AWS IAM identity (SigV4-signed STS token)
          +--------v---------+        +--------------------------+
          | API Gateway      |   or   | ALB + WAF                |
          |  -> Lambda       |        |  -> EC2 ASG (systemd)    |
          +--------+---------+        +------------+-------------+
                   +------------ adl-signer -------+
                    |            |              |
             KMS CA keys    DynamoDB       S3 archive (versioned, Object Lock)
             (dev, prod)    registry       certs, chains, CRLs, escrowed dev keys
```

## Installing the CLI

```sh
go install github.com/AUTORQ/adl-signing-server/cmd/adl@latest
adl install completion                 # tab completion for your shell
```

Or take your platform's binary from `make cli` (`dist/cli/`) and let it
install itself: `./adl-linux-amd64 install` puts it in `~/.local/bin` with
tab completion, `sudo ./adl-linux-amd64 install system` machine-wide.

`adl help` lists the commands, `adl <command> --help` shows a command's
flags, defaults and examples.

## Quick start by role

### Developer, minting a cert for a dev board

```sh
aws sso login --profile autorq-dev     # or however you normally get AWS creds
adl configure --url https://signer.example --region us-east-1 \
              --audience adl-signing-server:123456789012 --profile autorq-dev
adl mint --label board=rev-c --port /dev/ttyUSB0   # mint and flash
# -> certs/GLXADL017/device/device-GLXADL017.{crt,key}, -chain.pem,
#    ca-chain.pem, ca-root.pem
adl fetch GLXADL017                    # lost it? cert, key and root come back
adl ca pull --stage dev                # just the root / intermediate certs
```

See [docs/developer-guide.md](docs/developer-guide.md). The firmware reads
the identity from an `adl_certs` NVS partition; see
[docs/firmware-nvs.md](docs/firmware-nvs.md).

### Factory station

```sh
adl eol --help                         # the whole station walkthrough
adl eol check --station line-1
adl eol provision --station line-1 --port /dev/ttyUSB0 --firmware 1.4.2 --loop
```

See [docs/eol-provisioning.md](docs/eol-provisioning.md). The default flow
writes NVS and burns no eFuses. Try it on a few boards before a real run.

### Setting it up the first time

Deploy with [docs/operations.md](docs/operations.md), then do the CA
ceremony, and import any certificates you issued before, with
[docs/ca-ceremony.md](docs/ca-ceremony.md).

### Background

How it fits together is in [docs/architecture.md](docs/architecture.md),
and the security reasoning is in [docs/security.md](docs/security.md).
Serving several manufacturing partners from one deployment is in
[docs/partners.md](docs/partners.md).

## Repository layout

```
cmd/adl/                 CLI for developers, stations and admins
cmd/adl-signer/          the server (Lambda, EC2, or --local-insecure)
internal/pki/            certificate profile, CSR checks, CRLs
internal/kmssigner/      crypto.Signer backed by a KMS key
internal/service/        all business rules and permission checks
internal/auth/           IAM identity verification and the permission policy
internal/store/          DynamoDB registry (and an in-memory one)
internal/archive/        S3 archive (and an in-memory one)
internal/api/            HTTP handlers
internal/lambdahttp/     API Gateway v2 -> http.Handler adapter
internal/eol/            end-of-line station logic
scripts/eol/             flash and verify scripts the station runs
deploy/terraform/        modules: core, lambda, ec2; environments/example
docs/                    guides
```

## Building and testing

Go 1.26+ (the toolchain line in `go.mod` fetches the right one), Terraform
1.6+, Docker for the DynamoDB Local tests.

```sh
make build        # bin/adl, bin/adl-signer
make test         # everything, with -race
make test-dynamo  # registry tests against DynamoDB Local
make tf-check     # terraform fmt/validate + plan tests with a mocked provider
make dist         # lambda zip, ec2 binary, CLI for linux/mac/windows
make local        # whole server in memory on 127.0.0.1:8080, throwaway CA
```

`make local` plus `adl configure --url http://127.0.0.1:8080 --local` is the
quickest way to try the CLI or test firmware against certificates without
touching AWS. Those certificates chain to a throwaway root and are useless
anywhere else.
