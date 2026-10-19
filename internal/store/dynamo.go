package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/AUTORQ/adl-signing-server/internal/model"
)

// Single table layout. Terraform creates the table with the same names.
//
//	device        pk=DEVICE#<id>   sk=DEVICE        gsi1=ENV#<env> / <id>
//	certificate   pk=DEVICE#<id>   sk=CERT#<serial> gsi2=SERIAL#<serial>; gsi1=REVOKED#<env> once revoked
//	chip claim    pk=CHIP#<env>#<chip>  sk=CHIP
//	sequence      pk=SEQ#<name>    sk=SEQ
//	audit         pk=AUDIT#<day>   sk=<time>#<id>
const (
	attrPK     = "pk"
	attrSK     = "sk"
	attrGSI1PK = "gsi1pk"
	attrGSI1SK = "gsi1sk"
	attrGSI2PK = "gsi2pk"
	attrGSI2SK = "gsi2sk"
	attrType   = "item_type"

	IndexGSI1 = "gsi1"
	IndexGSI2 = "gsi2"
)

// DynamoAPI is the subset of the DynamoDB client used here.
type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// Dynamo is the production Store.
type Dynamo struct {
	api   DynamoAPI
	table string
}

func NewDynamo(api DynamoAPI, table string) *Dynamo {
	return &Dynamo{api: api, table: table}
}

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: s(pk), attrSK: s(sk)}
}

func devicePK(id string) string      { return "DEVICE#" + id }
func chipPK(env, chip string) string { return "CHIP#" + env + "#" + chip }

func (d *Dynamo) NextSequence(ctx context.Context, name string) (int64, error) {
	out, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.table),
		Key:                       key("SEQ#"+name, "SEQ"),
		UpdateExpression:          aws.String("ADD #n :one SET #t = :t"),
		ExpressionAttributeNames:  map[string]string{"#n": "n", "#t": attrType},
		ExpressionAttributeValues: map[string]types.AttributeValue{":one": &types.AttributeValueMemberN{Value: "1"}, ":t": s("sequence")},
		ReturnValues:              types.ReturnValueUpdatedNew,
	})
	if err != nil {
		return 0, fmt.Errorf("increment sequence %s: %w", name, err)
	}
	n, ok := out.Attributes["n"].(*types.AttributeValueMemberN)
	if !ok {
		return 0, errors.New("sequence update returned no value")
	}
	return strconv.ParseInt(n.Value, 10, 64)
}

func (d *Dynamo) EnsureSequenceAtLeast(ctx context.Context, name string, n int64) error {
	_, err := d.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.table),
		Key:                       key("SEQ#"+name, "SEQ"),
		UpdateExpression:          aws.String("SET #n = :n, #t = :t"),
		ConditionExpression:       aws.String("attribute_not_exists(#n) OR #n < :n"),
		ExpressionAttributeNames:  map[string]string{"#n": "n", "#t": attrType},
		ExpressionAttributeValues: map[string]types.AttributeValue{":n": &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}, ":t": s("sequence")},
	})
	if isConditionFailed(err) {
		return nil
	}
	return err
}

func (d *Dynamo) deviceItem(dev *model.Device) (map[string]types.AttributeValue, error) {
	item, err := attributevalue.MarshalMap(dev)
	if err != nil {
		return nil, err
	}
	item[attrPK] = s(devicePK(dev.ID))
	item[attrSK] = s("DEVICE")
	item[attrGSI1PK] = s("ENV#" + dev.Env)
	item[attrGSI1SK] = s(dev.ID)
	item[attrType] = s("device")
	return item, nil
}

func (d *Dynamo) chipClaim(dev *model.Device) types.TransactWriteItem {
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			attrPK: s(chipPK(dev.Env, dev.ChipID)), attrSK: s("CHIP"),
			"device_id": s(dev.ID), attrType: s("chip"),
		},
		ConditionExpression:       aws.String("attribute_not_exists(pk) OR device_id = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":id": s(dev.ID)},
	}}
}

func (d *Dynamo) CreateDevice(ctx context.Context, dev *model.Device) error {
	next := *dev
	next.Version = 1
	item, err := d.deviceItem(&next)
	if err != nil {
		return err
	}
	tx := []types.TransactWriteItem{{Put: &types.Put{
		TableName:           aws.String(d.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	}}}
	if dev.ChipID != "" {
		tx = append(tx, d.chipClaim(dev))
	}
	if err := d.transact(ctx, tx, dev.Env, dev.ChipID); err != nil {
		return err
	}
	dev.Version = 1
	return nil
}

func (d *Dynamo) UpdateDevice(ctx context.Context, dev *model.Device) error {
	next := *dev
	next.Version = dev.Version + 1
	item, err := d.deviceItem(&next)
	if err != nil {
		return err
	}
	tx := []types.TransactWriteItem{{Put: &types.Put{
		TableName:                 aws.String(d.table),
		Item:                      item,
		ConditionExpression:       aws.String("attribute_exists(pk) AND version = :v"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberN{Value: strconv.FormatInt(dev.Version, 10)}},
	}}}
	if dev.ChipID != "" {
		tx = append(tx, d.chipClaim(dev))
	}
	if err := d.transact(ctx, tx, dev.Env, dev.ChipID); err != nil {
		return err
	}
	dev.Version = next.Version
	return nil
}

// transact runs a device write plus optional chip claim and turns
// cancellation reasons into ErrConflict / ChipClaimedError.
func (d *Dynamo) transact(ctx context.Context, tx []types.TransactWriteItem, env, chip string) error {
	_, err := d.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: tx})
	if err == nil {
		return nil
	}
	var tce *types.TransactionCanceledException
	if errors.As(err, &tce) {
		for i, r := range tce.CancellationReasons {
			if aws.ToString(r.Code) != "ConditionalCheckFailed" {
				continue
			}
			if i == 1 && chip != "" {
				owner, lerr := d.DeviceIDForChip(ctx, env, chip)
				if lerr != nil {
					owner = "unknown"
				}
				return &ChipClaimedError{ChipID: chip, DeviceID: owner}
			}
			return ErrConflict
		}
	}
	return err
}

func (d *Dynamo) GetDevice(ctx context.Context, id string) (*model.Device, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            key(devicePK(id), "DEVICE"),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	var dev model.Device
	if err := attributevalue.UnmarshalMap(out.Item, &dev); err != nil {
		return nil, err
	}
	return &dev, nil
}

func (d *Dynamo) ListDevices(ctx context.Context, env string) ([]*model.Device, error) {
	var items []map[string]types.AttributeValue
	var err error
	if env == "" {
		items, err = d.scanType(ctx, "device")
	} else {
		items, err = d.query(ctx, &dynamodb.QueryInput{
			IndexName:                 aws.String(IndexGSI1),
			KeyConditionExpression:    aws.String("gsi1pk = :pk"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("ENV#" + env)},
		})
	}
	if err != nil {
		return nil, err
	}
	out := make([]*model.Device, 0, len(items))
	for _, it := range items {
		var dev model.Device
		if err := attributevalue.UnmarshalMap(it, &dev); err != nil {
			return nil, err
		}
		out = append(out, &dev)
	}
	return out, nil
}

func (d *Dynamo) DeviceIDForChip(ctx context.Context, env, chipID string) (string, error) {
	out, err := d.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(d.table),
		Key:            key(chipPK(env, chipID), "CHIP"),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return "", err
	}
	v, ok := out.Item["device_id"].(*types.AttributeValueMemberS)
	if !ok {
		return "", ErrNotFound
	}
	return v.Value, nil
}

func (d *Dynamo) certItem(c *model.Certificate) (map[string]types.AttributeValue, error) {
	item, err := attributevalue.MarshalMap(c)
	if err != nil {
		return nil, err
	}
	item[attrPK] = s(devicePK(c.DeviceID))
	item[attrSK] = s("CERT#" + c.Serial)
	item[attrGSI2PK] = s("SERIAL#" + c.Serial)
	item[attrGSI2SK] = s("CERT")
	item[attrType] = s("certificate")
	if c.Status == model.CertRevoked {
		// Sparse index: only revoked certs land in the CRL query.
		item[attrGSI1PK] = s("REVOKED#" + c.Env)
		item[attrGSI1SK] = s(c.Serial)
	}
	return item, nil
}

func (d *Dynamo) PutCertificate(ctx context.Context, c *model.Certificate) error {
	item, err := d.certItem(c)
	if err != nil {
		return err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(d.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if isConditionFailed(err) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) UpdateCertificate(ctx context.Context, c *model.Certificate) error {
	item, err := d.certItem(c)
	if err != nil {
		return err
	}
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(d.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_exists(pk)"),
	})
	if isConditionFailed(err) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) GetCertificate(ctx context.Context, serial string) (*model.Certificate, error) {
	items, err := d.query(ctx, &dynamodb.QueryInput{
		IndexName:                 aws.String(IndexGSI2),
		KeyConditionExpression:    aws.String("gsi2pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("SERIAL#" + serial)},
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	var c model.Certificate
	if err := attributevalue.UnmarshalMap(items[0], &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (d *Dynamo) ListCertificates(ctx context.Context, deviceID string) ([]*model.Certificate, error) {
	items, err := d.query(ctx, &dynamodb.QueryInput{
		KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :cert)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": s(devicePK(deviceID)), ":cert": s("CERT#"),
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	return unmarshalCerts(items)
}

func (d *Dynamo) ListRevoked(ctx context.Context, env string) ([]*model.Certificate, error) {
	items, err := d.query(ctx, &dynamodb.QueryInput{
		IndexName:                 aws.String(IndexGSI1),
		KeyConditionExpression:    aws.String("gsi1pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("REVOKED#" + env)},
	})
	if err != nil {
		return nil, err
	}
	return unmarshalCerts(items)
}

func unmarshalCerts(items []map[string]types.AttributeValue) ([]*model.Certificate, error) {
	out := make([]*model.Certificate, 0, len(items))
	for _, it := range items {
		var c model.Certificate
		if err := attributevalue.UnmarshalMap(it, &c); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, nil
}

// ClaimNonce writes a nonce marker that DynamoDB TTL cleans up later. The
// table has TTL enabled on the "expires_at" attribute.
func (d *Dynamo) ClaimNonce(ctx context.Context, nonce string, expires time.Time) error {
	_, err := d.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			attrPK: s("NONCE#" + nonce), attrSK: s("NONCE"), attrType: s("nonce"),
			"expires_at": &types.AttributeValueMemberN{Value: strconv.FormatInt(expires.Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if isConditionFailed(err) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) PutAudit(ctx context.Context, e *model.AuditEvent) error {
	item, err := attributevalue.MarshalMap(e)
	if err != nil {
		return err
	}
	item[attrPK] = s("AUDIT#" + DayKey(e.Time))
	item[attrSK] = s(e.Time.UTC().Format(time.RFC3339Nano) + "#" + e.ID)
	item[attrType] = s("audit")
	_, err = d.api.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table), Item: item})
	return err
}

func (d *Dynamo) ListAudit(ctx context.Context, day time.Time) ([]*model.AuditEvent, error) {
	items, err := d.query(ctx, &dynamodb.QueryInput{
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("AUDIT#" + DayKey(day))},
	})
	if err != nil {
		return nil, err
	}
	out := make([]*model.AuditEvent, 0, len(items))
	for _, it := range items {
		var e model.AuditEvent
		if err := attributevalue.UnmarshalMap(it, &e); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, nil
}

func (d *Dynamo) query(ctx context.Context, in *dynamodb.QueryInput) ([]map[string]types.AttributeValue, error) {
	in.TableName = aws.String(d.table)
	var items []map[string]types.AttributeValue
	p := dynamodb.NewQueryPaginator(d.api, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
	}
	return items, nil
}

func (d *Dynamo) scanType(ctx context.Context, typ string) ([]map[string]types.AttributeValue, error) {
	var items []map[string]types.AttributeValue
	p := dynamodb.NewScanPaginator(d.api, &dynamodb.ScanInput{
		TableName:                 aws.String(d.table),
		FilterExpression:          aws.String("#t = :t"),
		ExpressionAttributeNames:  map[string]string{"#t": attrType},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": s(typ)},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
	}
	return items, nil
}

func isConditionFailed(err error) bool {
	var ccf *types.ConditionalCheckFailedException
	return errors.As(err, &ccf)
}
