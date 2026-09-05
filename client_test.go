package dnsmadeeasy

import (
	"testing"
	"time"

	dme "github.com/john-k/dnsmadeeasy"
	"github.com/libdns/libdns"
)

func TestRecordRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		dme  dme.Record
	}{
		{"A", dme.Record{ID: 1, Type: "A", Name: "www", Value: "192.0.2.1", Ttl: 300}},
		{"AAAA", dme.Record{ID: 2, Type: "AAAA", Name: "www", Value: "2001:db8::1", Ttl: 301}},
		{"CNAME", dme.Record{ID: 3, Type: "CNAME", Name: "alias", Value: "target.example.", Ttl: 302}},
		{"MX", dme.Record{ID: 4, Type: "MX", Name: "@", Value: "mail.example.", MxLevel: 10, Ttl: 303}},
		{"TXT", dme.Record{ID: 5, Type: "TXT", Name: "_acme-challenge", Value: "token", Ttl: 304}},
		{"SRV", dme.Record{ID: 6, Type: "SRV", Name: "_sip._tcp", Value: "sip.example.", Priority: 10, Weight: 20, Port: 5060, Ttl: 305}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, err := recordFromDmeRecord(test.dme)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := dmeRecordFromRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			if actual.Type != test.dme.Type || actual.Name != test.dme.Name || actual.Value != test.dme.Value || actual.Ttl != test.dme.Ttl {
				t.Fatalf("round trip mismatch: got %#v, want %#v", actual, test.dme)
			}
			if actual.MxLevel != test.dme.MxLevel || actual.Priority != test.dme.Priority || actual.Weight != test.dme.Weight || actual.Port != test.dme.Port {
				t.Fatalf("type-specific fields mismatch: got %#v, want %#v", actual, test.dme)
			}
		})
	}
}

func TestDmeRecordFromNewTXT(t *testing.T) {
	record := libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: "token"}
	actual, err := dmeRecordFromRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if actual.ID != 0 || actual.Type != "TXT" || actual.Name != record.Name || actual.Value != record.Text || actual.Ttl != 60 {
		t.Fatalf("unexpected DME record: %#v", actual)
	}
}

func TestRecordFromDmeAddress(t *testing.T) {
	record, err := recordFromDmeRecord(dme.Record{ID: 42, Type: "A", Name: "www", Value: "192.0.2.1", Ttl: 120})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := record.(libdns.Address); !ok {
		t.Fatalf("got %T, want libdns.Address", record)
	}
	rr := record.RR()
	if rr.Type != "A" || rr.Name != "www" || rr.Data != "192.0.2.1" || rr.TTL != 120*time.Second {
		t.Fatalf("unexpected record: %#v", rr)
	}
}

func TestRecordFromDmeMalformedRecord(t *testing.T) {
	record, err := recordFromDmeRecord(dme.Record{Type: "CAA", Name: "@", Value: "malformed", Ttl: 120})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := record.(libdns.RR); !ok {
		t.Fatalf("got %T, want libdns.RR", record)
	}
}

func TestRecordsMatch(t *testing.T) {
	candidate := libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: "token"}
	for _, test := range []struct {
		name   string
		record libdns.Record
		match  bool
	}{
		{"exact", libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: time.Minute, Data: "token"}, true},
		{"wildcard fields", libdns.RR{Name: "_acme-challenge"}, true},
		{"different name", libdns.RR{Name: "other"}, false},
		{"different type", libdns.RR{Name: "_acme-challenge", Type: "CNAME"}, false},
		{"different TTL", libdns.RR{Name: "_acme-challenge", TTL: time.Hour}, false},
		{"different value", libdns.RR{Name: "_acme-challenge", Data: "other"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if match := recordsMatch(test.record, candidate); match != test.match {
				t.Fatalf("recordsMatch() = %t, want %t", match, test.match)
			}
		})
	}
}
