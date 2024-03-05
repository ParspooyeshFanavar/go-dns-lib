package dnslib

import (
	"github.com/miekg/dns"
)

type ParsePacketResult struct {
	Schema  *DnsSchema
	Msg     *dns.Msg
	Payload []byte
}
