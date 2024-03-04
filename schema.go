package dnslib

import (
	"strings"

	"github.com/miekg/dns"
)

const (
	DnsAnswer     = iota
	DnsAuthority  = iota
	DnsAdditional = iota
)

// JSON serialization only supports nullifying types that can accept nil.
// The ECS fields are pointers because they're nullable.
type DnsSchema struct {
	Timestamp          int64   `json:"timestamp"`
	Sha256             string  `json:"sha256,omitempty"`
	Udp                bool    `json:"udp,omitempty"`
	Ipv4               bool    `json:"ipv4,omitempty"`
	SourceAddress      string  `json:"src_address"`
	SourcePort         uint16  `json:"src_port"`
	DestinationAddress string  `json:"dst_address"`
	DestinationPort    uint16  `json:"dst_port"`
	Id                 uint16  `json:"id,omitempty"`
	Rcode              int     `json:"rcode,omitempty"`
	Truncated          bool    `json:"truncated,omitempty"`
	Response           bool    `json:"response,omitempty"`
	RecursionDesired   bool    `json:"recursion_desired,omitempty"`
	Answer             bool    `json:"answer,omitempty"`
	Authority          bool    `json:"authority,omitempty"`
	Additional         bool    `json:"additional,omitempty"`
	Qname              string  `json:"qname,omitempty"`
	Qtype              uint16  `json:"qtype,omitempty"`
	Ttl                *uint32 `json:"ttl,omitempty"`
	Rname              *string `json:"rname,omitempty"`
	Rtype              *uint16 `json:"rtype,omitempty"`
	Rdata              *string `json:"rdata,omitempty"`
	EcsClient          *string `json:"ecs_client,omitempty"`
	EcsSource          *uint8  `json:"ecs_source,omitempty"`
	EcsScope           *uint8  `json:"ecs_scope,omitempty"`
	Source             string  `json:"source,omitempty"`
	Sensor             string  `json:"sensor,omitempty"`
}

var (
	Initializers = make(map[string]func())
	Marshalers   = make(map[string]func(*DnsSchema))
	Closers      = make(map[string]func())
)

func Initialize(format string) {
	if init, ok := Initializers[format]; ok {
		init()
	}
}

func Close(format string) {
	if closer, ok := Closers[format]; ok {
		closer()
	}
}

func (d DnsSchema) Marshal(rr *dns.RR, section int, format string) {
	if rr != nil {
		// This works because RR.Header().String() prefixes the RDATA
		// in the RR.String() representation.
		// Reference: https://github.com/miekg/dns/blob/master/types.go
		rdata := strings.TrimPrefix((*rr).String(), (*rr).Header().String())

		// Fill in the rest of the parameters
		// This will not alter the underlying DNS schema
		d.Ttl = &(*rr).Header().Ttl
		d.Rname = &(*rr).Header().Name
		d.Rtype = &(*rr).Header().Rrtype
		d.Rdata = &rdata
		d.Answer = section == DnsAnswer
		d.Authority = section == DnsAuthority
		d.Additional = section == DnsAdditional

		// Ignore OPT records
		if *d.Rtype == 41 {
			return
		}
	}

	Marshalers[format](&d)
}
