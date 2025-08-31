package dnsmadeeasy

import (
	"context"
	"fmt"
	"strconv"
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

func recordFromDmeRecord(dmeRecord dme.Record) (libdns.Record, error) {
	return libdns.RR{
		ID:   fmt.Sprint(dmeRecord.ID),
		Name: dmeRecord.Name,
		TTL:  time.Duration(dmeRecord.Ttl),
		Type: dmeRecord.Type,
		Data: dmeRecord.Value,
	}.Parse()
}

func dmeRecordFromRecord(r libdns.Record) (dme.Record, error) {
	var dmeRecord dme.Record
	var id int
	var err error
	rr := r.RR()
	// Since dmeRecord.ID is set to `json:"id,omitempty"`, this properly preserves empty values
	if rr.ID == "" {
		id = 0
	} else {
		id, err = strconv.Atoi(rr.ID)
		if err != nil {
			return dme.Record{}, err
		}
	}
	dmeRecord.ID = id
	dmeRecord.Name = rr.Name
	dmeRecord.Type = rr.Type
	dmeRecord.Value = rr.Data
	dmeRecord.Ttl = int(rr.TTL.Seconds())
	// DNSMadeEasy fails to accept zero TTL, so use a default value
	if dmeRecord.Ttl == 0 {
		dmeRecord.Ttl = 120
	}
	// Likewise, DNSMadeEasy doesn't accept a blank GtdLocation
	dmeRecord.GtdLocation = "DEFAULT"
	if rr.Type == "MX" {
		mx_rec, err := rr.Parse()
		if err != nil {
			return dme.Record{}, err
		}
		dmeRecord.MxLevel = int(mx_rec.Preference)
	} else if rr.Type == "SRV" {
		srv_rec, err := rr.Parse()
		if err != nil {
			return dme.Record{}, err
		}
		dmeRecord.Priority = int(srv_rec.Priority)
		/*
			// TODO: enable support for SRV weight field and extracting
			// "<port> <target>" from value when libdns releases support
			dmeRecord.Weight = record.Weight
			fields := strings.Fields(record.Value)
			if len(fields) != 2 {
				return dme.Record{}, fmt.Errorf("malformed SRV value '%s'; expected: '<port> <target>'", record.Value)
			}

			port, err := strconv.Atoi(fields[0])
			if err != nil {
				return dme.Record{}, fmt.Errorf("invalid port %s: %v", fields[0], err)
			}
			if port < 0 {
				return dme.Record{}, fmt.Errorf("port cannot be < 0: %d", port)
			}
			dmeRecord.Port = port
			dmeRecord.Value = fields[1]
		*/
	}
	return dmeRecord, nil

}
