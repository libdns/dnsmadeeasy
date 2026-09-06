package dnsmadeeasy

import (
	"context"
	"fmt"
	"strings"
	"time"

	dme "github.com/john-k/dnsmadeeasy"
	"github.com/libdns/libdns"
)

func (p *Provider) init(ctx context.Context) {
	p.once.Do(func() {
		p.client = *dme.GetClient(
			p.APIKey,
			p.SecretKey,
			p.APIEndpoint,
		)
	})
}

func recordFromDmeRecord(record dme.Record) (libdns.Record, error) {
	data := strings.Trim(record.Value, "\"")
	if record.Type == "MX" {
		data = fmt.Sprintf("%d %s", record.MxLevel, data)
	} else if record.Type == "SRV" {
		data = fmt.Sprintf("%d %d %d %s", record.Priority, record.Weight, record.Port, data)
	}

	rr := libdns.RR{
		Name: record.Name,
		TTL:  time.Duration(record.Ttl) * time.Second,
		Type: record.Type,
		Data: data,
	}
	parsed, err := rr.Parse()
	if err != nil {
		return rr, nil
	}
	return parsed, nil
}

func dmeRecordFromRecord(record libdns.Record) (dme.Record, error) {
	rr := record.RR()
	dmeRecord := dme.Record{
		Name:        rr.Name,
		Type:        rr.Type,
		Value:       rr.Data,
		Ttl:         int(rr.TTL.Seconds()),
		GtdLocation: "DEFAULT",
	}
	if dmeRecord.Ttl == 0 {
		dmeRecord.Ttl = 120
	}

	parsed, err := rr.Parse()
	if err != nil {
		return dme.Record{}, err
	}
	if rr.Type == "MX" {
		mx := parsed.(libdns.MX)
		dmeRecord.MxLevel = int(mx.Preference)
		dmeRecord.Value = mx.Target
	} else if rr.Type == "SRV" {
		srv := parsed.(libdns.SRV)
		dmeRecord.Priority = int(srv.Priority)
		dmeRecord.Weight = int(srv.Weight)
		dmeRecord.Port = int(srv.Port)
		dmeRecord.Value = srv.Target
	}

	return dmeRecord, nil
}

func recordsMatch(record, candidate libdns.Record) bool {
	rr := record.RR()
	candidateRR := candidate.RR()
	return rr.Name == candidateRR.Name &&
		(rr.Type == "" || rr.Type == candidateRR.Type) &&
		(rr.TTL == 0 || rr.TTL == candidateRR.TTL) &&
		(rr.Data == "" || rr.Data == candidateRR.Data)
}
