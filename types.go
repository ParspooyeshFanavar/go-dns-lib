package dnslib

import (
	"github.com/miekg/dns"
)

type Request struct {
	Schema  *DnsSchema
	Msg     *dns.Msg
	Payload []byte
}
