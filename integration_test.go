package dnsmadeeasy

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	dme "github.com/john-k/dnsmadeeasy"
	"github.com/libdns/libdns"
)

func TestAppendAndDeleteRecord(t *testing.T) {
	apiKey := os.Getenv("DNSMADEEASY_API_KEY")
	secretKey := os.Getenv("DNSMADEEASY_SECRET_KEY")
	zone := os.Getenv("DNSMADEEASY_TEST_ZONE")
	if apiKey == "" || secretKey == "" || zone == "" {
		t.Skip("DNS Made Easy integration test credentials are not set")
	}
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	provider := &Provider{
		APIKey:      apiKey,
		SecretKey:   secretKey,
		APIEndpoint: dme.Prod,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	removeTestRecords(t, provider, ctx, zone)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		removeTestRecords(t, provider, cleanupCtx, zone)
	}()

	record := libdns.TXT{
		Name: fmt.Sprintf("_libdns-test-%d", time.Now().UnixNano()),
		TTL:  5 * time.Minute,
		Text: "libdns-dnsmadeeasy integration test",
	}
	created, err := provider.AppendRecords(ctx, zone, []libdns.Record{record})
	if err != nil {
		t.Fatalf("append record: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("AppendRecords returned %d records, want 1", len(created))
	}
	if _, ok := created[0].(libdns.TXT); !ok {
		t.Fatalf("AppendRecords returned %T, want libdns.TXT", created[0])
	}

	createdRR := created[0].RR()

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("get records after append: %v", err)
	}
	if !containsRecord(records, createdRR) {
		var candidates []libdns.RR
		for _, record := range records {
			if strings.HasPrefix(record.RR().Name, "_libdns-test-") {
				candidates = append(candidates, record.RR())
			}
		}
		t.Fatalf("appended record %#v was not returned by GetRecords; test records: %#v", createdRR, candidates)
	}

	deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{createdRR})
	if err != nil {
		t.Fatalf("delete record: %v", err)
	}
	if len(deleted) != 1 || !recordsMatch(createdRR, deleted[0]) {
		t.Fatalf("DeleteRecords returned %#v, want the created record", deleted)
	}

	records, err = provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("get records after delete: %v", err)
	}
	if containsRecord(records, createdRR) {
		t.Fatal("deleted record was still returned by GetRecords")
	}
}

func removeTestRecords(t *testing.T, provider *Provider, ctx context.Context, zone string) {
	t.Helper()
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("find test records for cleanup: %v", err)
	}
	var testRecords []libdns.Record
	for _, record := range records {
		if strings.HasPrefix(record.RR().Name, "_libdns-test-") {
			testRecords = append(testRecords, record)
		}
	}
	if len(testRecords) == 0 {
		return
	}
	if _, err := provider.DeleteRecords(ctx, zone, testRecords); err != nil {
		t.Fatalf("cleanup test records: %v", err)
	}
}

func containsRecord(records []libdns.Record, target libdns.Record) bool {
	for _, record := range records {
		if recordsMatch(target, record) {
			return true
		}
	}
	return false
}
