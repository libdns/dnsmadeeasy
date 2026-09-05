package dnsmadeeasy

import (
	"context"
	"slices"
	"strings"
	"sync"

	dme "github.com/john-k/dnsmadeeasy"
	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with DNSMadeEasy
type Provider struct {
	APIKey      string      `json:"api_key,omitempty"`
	SecretKey   string      `json:"secret_key,omitempty"`
	APIEndpoint dme.BaseURL `json:"api_endpoint,omitempty"`
	client      dme.Client
	once        sync.Once
	mutex       sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	var records []libdns.Record

	// first, get the ID for our zone name -- dnsmadeeasy doesn't use the trailing dot
	zoneId, err := p.client.IdForDomain(strings.TrimRight(zone, "."))
	if err != nil {
		return nil, err
	}

	// get an array of DNSMadeEasy Records for our zone
	dmeRecords, err := p.client.EnumerateRecords(zoneId)
	if err != nil {
		return nil, err
	}

	// translate each DNSMadeEasy Domain Record to a libdns Record
	for _, rec := range dmeRecords {
		record, err := recordFromDmeRecord(rec)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func createRecords(client dme.Client, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var dmeRecords []dme.Record
	// first, get the ID for our zone name -- dnsmadeeasy doesn't use the trailing dot
	zoneId, err := client.IdForDomain(strings.TrimRight(zone, "."))
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		dmeRecord, err := dmeRecordFromRecord(record)
		if err != nil {
			return []libdns.Record{}, err
		}
		dmeRecords = append(dmeRecords, dmeRecord)
	}

	newDmeRecords, err := client.CreateRecords(zoneId, dmeRecords)
	if err != nil {
		return nil, err
	}

	var newRecords []libdns.Record
	for _, dmeRec := range newDmeRecords {
		newRec, err := recordFromDmeRecord(dmeRec)
		if err != nil {
			return nil, err
		}
		newRecords = append(newRecords, newRec)
	}

	return newRecords, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	return createRecords(p.client, zone, records)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	// first, get the ID for our zone name -- dnsmadeeasy doesn't use the trailing dot
	zoneId, err := p.client.IdForDomain(strings.TrimRight(zone, "."))
	if err != nil {
		return nil, err
	}

	// get an array of DNSMadeEasy Records for our zone
	dmeRecords, err := p.client.EnumerateRecords(zoneId)
	if err != nil {
		return nil, err
	}

	// split our input records into those that need updating and those that need creating.
	// if an ID is not provided in the record, try to match based on Type and Name
	var newRecords []libdns.Record
	var dmeRecordsToUpdate []dme.Record
	for _, record := range records {
		rr := record.RR()
		foundIdx := slices.IndexFunc(dmeRecords, func(dmeRecord dme.Record) bool {
			return rr.Type == dmeRecord.Type && rr.Name == dmeRecord.Name
		})
		if foundIdx == -1 {
			newRecords = append(newRecords, record)
		} else {
			dmeRecord, err := dmeRecordFromRecord(record)
			if err != nil {
				return nil, err
			}
			dmeRecord.ID = dmeRecords[foundIdx].ID
			dmeRecordsToUpdate = append(dmeRecordsToUpdate, dmeRecord)
		}
	}

	// update existing records
	// Note: this is performed first so that we don't leave our request
	// in a half-applied state
	updatedDmeRecords, err := p.client.UpdateRecords(zoneId, dmeRecordsToUpdate)
	if err != nil {
		return nil, err
	}

	// convert the DME Records to libdns records
	var updatedRecords []libdns.Record
	for _, record := range updatedDmeRecords {
		updatedRecord, err := recordFromDmeRecord(record)
		if err != nil {
			return nil, err
		}
		updatedRecords = append(updatedRecords, updatedRecord)
	}

	// create new records
	createdRecords, err := createRecords(p.client, zone, newRecords)
	if err != nil {
		return nil, err
	}

	// TODO: hopefully record ordering in the array isn't important
	return append(updatedRecords, createdRecords...), nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.init(ctx)

	// first, get the ID for our zone name -- dnsmadeeasy doesn't use the trailing dot
	zoneId, err := p.client.IdForDomain(strings.TrimRight(zone, "."))
	if err != nil {
		return nil, err
	}

	dmeRecords, err := p.client.EnumerateRecords(zoneId)
	if err != nil {
		return nil, err
	}

	var recordsToDelete []int
	recordsByID := make(map[int]libdns.Record)
	for _, dmeRecord := range dmeRecords {
		candidate, err := recordFromDmeRecord(dmeRecord)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if recordsMatch(record, candidate) {
				recordsToDelete = append(recordsToDelete, dmeRecord.ID)
				recordsByID[dmeRecord.ID] = candidate
				break
			}
		}
	}
	if len(recordsToDelete) == 0 {
		return []libdns.Record{}, nil
	}

	deletedRecords, err := p.client.DeleteRecords(zoneId, recordsToDelete)
	if err != nil {
		return nil, err
	}

	var returnRecords []libdns.Record
	for _, id := range deletedRecords {
		if record, ok := recordsByID[id]; ok {
			returnRecords = append(returnRecords, record)
		}
	}

	return returnRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
