// Package archive keeps durable copies of every certificate, chain and
// escrowed developer key. In AWS it is a versioned, object-locked S3 bucket.
package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

var (
	ErrNotFound = errors.New("object not found")
	ErrExists   = errors.New("object already exists")
)

// PutOptions controls how an object is written.
type PutOptions struct {
	ContentType string
	// Sensitive objects (private keys) are encrypted with the escrow KMS
	// key, which only the service role and break-glass admins can use.
	Sensitive bool
	// NoOverwrite fails with ErrExists if the key is already present.
	NoOverwrite bool
}

type Store interface {
	Put(ctx context.Context, key string, data []byte, opts PutOptions) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// Object key layout, kept in one place so the docs and IAM policies agree.
func CertificateKey(env, deviceID, serial string) string {
	return fmt.Sprintf("certificates/%s/%s/%s/certificate.pem", env, deviceID, serial)
}

func ChainKey(env, deviceID, serial string) string {
	return fmt.Sprintf("certificates/%s/%s/%s/chain.pem", env, deviceID, serial)
}

func CertificatePrefix(env, deviceID, serial string) string {
	return fmt.Sprintf("certificates/%s/%s/%s/", env, deviceID, serial)
}

func EscrowKey(env, deviceID, serial string) string {
	return fmt.Sprintf("escrow/%s/%s/%s/private-key.pem", env, deviceID, serial)
}

func CAChainKey(env string) string { return fmt.Sprintf("ca/%s/chain.pem", env) }

func CRLKey(env string) string { return fmt.Sprintf("ca/%s/current.crl", env) }

// S3API is the subset of the S3 client used here.
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3 stores objects in a bucket with SSE-KMS.
type S3 struct {
	api         S3API
	bucket      string
	dataKeyID   string
	escrowKeyID string
}

func NewS3(api S3API, bucket, dataKeyID, escrowKeyID string) *S3 {
	return &S3{api: api, bucket: bucket, dataKeyID: dataKeyID, escrowKeyID: escrowKeyID}
}

func (s *S3) Put(ctx context.Context, key string, data []byte, opts PutOptions) error {
	in := &s3.PutObjectInput{
		Bucket:               aws.String(s.bucket),
		Key:                  aws.String(key),
		Body:                 bytes.NewReader(data),
		ContentType:          aws.String(opts.ContentType),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		// Object Lock needs an integrity checksum on every put.
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	}
	if opts.Sensitive {
		if s.escrowKeyID == "" {
			return errors.New("escrow kms key is not configured")
		}
		in.SSEKMSKeyId = aws.String(s.escrowKeyID)
	} else if s.dataKeyID != "" {
		in.SSEKMSKeyId = aws.String(s.dataKeyID)
		in.BucketKeyEnabled = aws.Bool(true)
	}
	if opts.NoOverwrite {
		in.IfNoneMatch = aws.String("*")
	}
	_, err := s.api.PutObject(ctx, in)
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && (ae.ErrorCode() == "PreconditionFailed" || ae.ErrorCode() == "ConditionalRequestConflict") {
			return ErrExists
		}
		return fmt.Errorf("s3 put %s: %w", key, err)
	}
	return nil
}

func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("s3 get %s: %w", key, err)
	}
	defer out.Body.Close()
	return io.ReadAll(io.LimitReader(out.Body, 4<<20))
}

// Memory is an in-process Store for tests and local mode.
type Memory struct {
	mu      sync.Mutex
	Objects map[string][]byte
	// SensitiveKeys records which objects were written as sensitive so
	// tests can assert keys went through the escrow path.
	SensitiveKeys map[string]bool
}

func NewMemory() *Memory {
	return &Memory{Objects: map[string][]byte{}, SensitiveKeys: map[string]bool{}}
}

func (m *Memory) Put(_ context.Context, key string, data []byte, opts PutOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Objects[key]; ok && opts.NoOverwrite {
		return ErrExists
	}
	m.Objects[key] = bytes.Clone(data)
	m.SensitiveKeys[key] = opts.Sensitive
	return nil
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.Objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(b), nil
}
