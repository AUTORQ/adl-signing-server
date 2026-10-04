package kmssigner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Fake is an in-memory stand-in for KMS backed by a local key. It is used by
// tests and the signer's local mode, never in AWS.
type Fake struct {
	Key   crypto.Signer
	ID    string
	Calls atomic.Int64
}

func (f *Fake) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(f.Key.Public())
	if err != nil {
		return nil, err
	}
	var algs []types.SigningAlgorithmSpec
	switch f.Key.Public().(type) {
	case *rsa.PublicKey:
		algs = []types.SigningAlgorithmSpec{
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
			types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecRsassaPssSha256,
			types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecRsassaPssSha512,
		}
	case *ecdsa.PublicKey:
		algs = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256, types.SigningAlgorithmSpecEcdsaSha384}
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             aws.String(f.ID),
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         der,
		SigningAlgorithms: algs,
	}, nil
}

func (f *Fake) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.Calls.Add(1)
	if in.MessageType != types.MessageTypeDigest {
		return nil, errors.New("fake kms only supports DIGEST messages")
	}
	var opts crypto.SignerOpts
	switch in.SigningAlgorithm {
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecEcdsaSha256:
		opts = crypto.SHA256
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecEcdsaSha384:
		opts = crypto.SHA384
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		opts = crypto.SHA512
	case types.SigningAlgorithmSpecRsassaPssSha256:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	case types.SigningAlgorithmSpecRsassaPssSha384:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}
	case types.SigningAlgorithmSpecRsassaPssSha512:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}
	default:
		return nil, fmt.Errorf("fake kms: unsupported algorithm %s", in.SigningAlgorithm)
	}
	if len(in.Message) != opts.HashFunc().Size() {
		return nil, errors.New("fake kms: digest length does not match algorithm")
	}
	sig, err := f.Key.Sign(rand.Reader, in.Message, opts)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{KeyId: aws.String(f.ID), Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
}
