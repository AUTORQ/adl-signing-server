// Package kmssigner implements crypto.Signer on top of an asymmetric AWS KMS
// key. The CA private keys never leave KMS; we only ever send it digests.
package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// API is the slice of the KMS client we use.
type API interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer signs digests with a KMS key.
type Signer struct {
	api     API
	keyID   string
	pub     crypto.PublicKey
	algs    []types.SigningAlgorithmSpec
	timeout time.Duration
}

// New fetches the public key for keyID and checks it is a signing key.
func New(ctx context.Context, api API, keyID string) (*Signer, error) {
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms get public key %s: %w", keyID, err)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms key %s has usage %s, need SIGN_VERIFY", keyID, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse kms public key: %w", err)
	}
	id := keyID
	if out.KeyId != nil {
		id = *out.KeyId
	}
	return &Signer{api: api, keyID: id, pub: pub, algs: out.SigningAlgorithms, timeout: 15 * time.Second}, nil
}

// KeyID is the full ARN of the KMS key.
func (s *Signer) KeyID() string { return s.keyID }

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer. digest must already be hashed with
// opts.HashFunc().
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := s.algorithm(opts)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(s.algs, alg) {
		return nil, fmt.Errorf("kms key %s does not support %s", s.keyID, alg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: alg,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return out.Signature, nil
}

func (s *Signer) algorithm(opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	h := opts.HashFunc()
	switch s.pub.(type) {
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			// KMS always uses a salt the size of the digest.
			if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != h.Size() {
				return "", errors.New("kms only supports PSS with salt length equal to the hash size")
			}
			switch h {
			case crypto.SHA256:
				return types.SigningAlgorithmSpecRsassaPssSha256, nil
			case crypto.SHA384:
				return types.SigningAlgorithmSpecRsassaPssSha384, nil
			case crypto.SHA512:
				return types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
		} else {
			switch h {
			case crypto.SHA256:
				return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
			case crypto.SHA384:
				return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
			case crypto.SHA512:
				return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
			}
		}
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		}
	}
	return "", fmt.Errorf("no kms signing algorithm for %T with hash %v", s.pub, h)
}
