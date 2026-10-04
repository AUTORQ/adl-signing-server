package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/edge-labs/adl-signing-server/internal/model"
	"github.com/edge-labs/adl-signing-server/internal/store"
)

func TestMemory(t *testing.T) { conformance(t, store.NewMemory()) }

// TestDynamoLocal runs the same checks against DynamoDB Local. Start one with
//
//	docker run --rm -p 8000:8000 amazon/dynamodb-local
//
// and set ADL_TEST_DYNAMO_ENDPOINT=http://127.0.0.1:8000.
func TestDynamoLocal(t *testing.T) {
	endpoint := os.Getenv("ADL_TEST_DYNAMO_ENDPOINT")
	if endpoint == "" {
		t.Skip("ADL_TEST_DYNAMO_ENDPOINT not set")
	}
	client := dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
	table := fmt.Sprintf("adl-test-%d", time.Now().UnixNano())
	if err := CreateTable(context.Background(), client, table); err != nil {
		t.Fatal(err)
	}
	conformance(t, store.NewDynamo(client, table))
}

// CreateTable mirrors the Terraform definition of the registry table.
func CreateTable(ctx context.Context, c *dynamodb.Client, name string) error {
	str := types.ScalarAttributeTypeS
	_, err := c.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(name),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("pk"), AttributeType: str},
			{AttributeName: aws.String("sk"), AttributeType: str},
			{AttributeName: aws.String("gsi1pk"), AttributeType: str},
			{AttributeName: aws.String("gsi1sk"), AttributeType: str},
			{AttributeName: aws.String("gsi2pk"), AttributeType: str},
			{AttributeName: aws.String("gsi2sk"), AttributeType: str},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("sk"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String(store.IndexGSI1),
				KeySchema: []types.KeySchemaElement{
					{AttributeName: aws.String("gsi1pk"), KeyType: types.KeyTypeHash},
					{AttributeName: aws.String("gsi1sk"), KeyType: types.KeyTypeRange},
				},
				Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
			},
			{
				IndexName: aws.String(store.IndexGSI2),
				KeySchema: []types.KeySchemaElement{
					{AttributeName: aws.String("gsi2pk"), KeyType: types.KeyTypeHash},
					{AttributeName: aws.String("gsi2sk"), KeyType: types.KeyTypeRange},
				},
				Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
			},
		},
	})
	return err
}

func conformance(t *testing.T, s store.Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	t.Run("sequence", func(t *testing.T) {
		var wg sync.WaitGroup
		seen := sync.Map{}
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := s.NextSequence(ctx, "seq-test")
				if err != nil {
					t.Error(err)
					return
				}
				if _, dup := seen.LoadOrStore(n, true); dup {
					t.Errorf("duplicate sequence value %d", n)
				}
			}()
		}
		wg.Wait()
		if err := s.EnsureSequenceAtLeast(ctx, "seq-test", 100); err != nil {
			t.Fatal(err)
		}
		if err := s.EnsureSequenceAtLeast(ctx, "seq-test", 50); err != nil {
			t.Fatal(err)
		}
		n, err := s.NextSequence(ctx, "seq-test")
		if err != nil || n != 101 {
			t.Fatalf("got %d %v, want 101", n, err)
		}
	})

	t.Run("devices", func(t *testing.T) {
		d := &model.Device{ID: "DEV1", Env: "dev", Status: model.DeviceIssued, Owner: "alice", ChipID: "aabbcc", CreatedAt: now, UpdatedAt: now, Labels: map[string]string{"board": "rev-c"}}
		if err := s.CreateDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
		if d.Version != 1 {
			t.Errorf("version %d after create", d.Version)
		}
		if err := s.CreateDevice(ctx, &model.Device{ID: "DEV1", Env: "dev"}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("duplicate create: %v", err)
		}
		// Same chip on a different device must be refused.
		err := s.CreateDevice(ctx, &model.Device{ID: "DEV2", Env: "dev", ChipID: "aabbcc", CreatedAt: now})
		var claimed *store.ChipClaimedError
		if !errors.As(err, &claimed) || claimed.DeviceID != "DEV1" {
			t.Fatalf("expected chip claimed by DEV1, got %v", err)
		}
		if _, err := s.GetDevice(ctx, "DEV2"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DEV2 should not exist after failed create: %v", err)
		}

		got, err := s.GetDevice(ctx, "DEV1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Labels["board"] != "rev-c" || !got.CreatedAt.Equal(now) {
			t.Errorf("round trip mismatch: %+v", got)
		}
		stale := *got
		got.Status = model.DeviceProvisioned
		if err := s.UpdateDevice(ctx, got); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateDevice(ctx, &stale); !errors.Is(err, store.ErrConflict) {
			t.Errorf("stale update should conflict, got %v", err)
		}
		id, err := s.DeviceIDForChip(ctx, "aabbcc")
		if err != nil || id != "DEV1" {
			t.Errorf("chip lookup: %q %v", id, err)
		}

		if err := s.CreateDevice(ctx, &model.Device{ID: "PROD1", Env: "prod", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		list, err := s.ListDevices(ctx, "dev")
		if err != nil || len(list) != 1 || list[0].ID != "DEV1" {
			t.Errorf("list dev: %v %v", list, err)
		}
		all, err := s.ListDevices(ctx, "")
		if err != nil || len(all) != 2 {
			t.Errorf("list all: %d %v", len(all), err)
		}
	})

	t.Run("certificates", func(t *testing.T) {
		c := &model.Certificate{Serial: "ABC123", DeviceID: "DEV1", Env: "dev", Status: model.CertActive, IssuedAt: now, NotAfter: now.Add(time.Hour)}
		if err := s.PutCertificate(ctx, c); err != nil {
			t.Fatal(err)
		}
		if err := s.PutCertificate(ctx, c); !errors.Is(err, store.ErrConflict) {
			t.Errorf("duplicate cert put: %v", err)
		}
		got, err := s.GetCertificate(ctx, "ABC123")
		if err != nil || got.DeviceID != "DEV1" {
			t.Fatalf("get cert: %+v %v", got, err)
		}
		if rev, _ := s.ListRevoked(ctx, "dev"); len(rev) != 0 {
			t.Errorf("nothing should be revoked yet: %v", rev)
		}
		got.Status = model.CertRevoked
		got.RevocationReason = "keyCompromise"
		if err := s.UpdateCertificate(ctx, got); err != nil {
			t.Fatal(err)
		}
		rev, err := s.ListRevoked(ctx, "dev")
		if err != nil || len(rev) != 1 {
			t.Errorf("revoked list: %v %v", rev, err)
		}
		if rev, _ := s.ListRevoked(ctx, "prod"); len(rev) != 0 {
			t.Errorf("prod should have no revocations: %v", rev)
		}
		list, err := s.ListCertificates(ctx, "DEV1")
		if err != nil || len(list) != 1 {
			t.Errorf("list certs: %v %v", list, err)
		}
		if _, err := s.GetCertificate(ctx, "NOPE"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("missing cert: %v", err)
		}
	})

	t.Run("nonce", func(t *testing.T) {
		exp := time.Now().Add(time.Minute)
		if err := s.ClaimNonce(ctx, "n1", exp); err != nil {
			t.Fatal(err)
		}
		if err := s.ClaimNonce(ctx, "n1", exp); !errors.Is(err, store.ErrConflict) {
			t.Errorf("replayed nonce: %v", err)
		}
	})

	t.Run("audit", func(t *testing.T) {
		if err := s.PutAudit(ctx, &model.AuditEvent{ID: "1", Time: now, Actor: "alice", Action: "issue"}); err != nil {
			t.Fatal(err)
		}
		evs, err := s.ListAudit(ctx, now)
		if err != nil || len(evs) != 1 || evs[0].Action != "issue" {
			t.Errorf("audit: %v %v", evs, err)
		}
	})
}
