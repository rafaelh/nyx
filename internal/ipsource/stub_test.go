package ipsource_test

import (
	"context"
	"sync"

	"github.com/rafaelh/nyx/internal/egress"
)

// httpStub answers each request with the reply registered for its URL, and
// records the URLs asked in order.
type httpStub struct {
	mu      sync.Mutex
	replies map[string]egress.ThirdPartyResponse
	errs    map[string]error
	asked   []string
}

func (s *httpStub) Do(_ context.Context, r egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, r.URL)
	if err := s.errs[r.URL]; err != nil {
		return egress.ThirdPartyResponse{}, err
	}
	if resp, ok := s.replies[r.URL]; ok {
		return resp, nil
	}
	return egress.ThirdPartyResponse{Status: 404}, nil
}

func (s *httpStub) count(url string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.asked {
		if a == url {
			n++
		}
	}
	return n
}

func ok(body string) egress.ThirdPartyResponse {
	return egress.ThirdPartyResponse{Status: 200, Body: []byte(body)}
}

// dnsStub answers each query name with the result registered for it.
type dnsStub struct {
	results map[string]egress.DNSResult
	err     error
	asked   []string
}

func (s *dnsStub) Query(_ context.Context, name string, _ uint16) (egress.DNSResult, error) {
	s.asked = append(s.asked, name)
	if s.err != nil {
		return egress.DNSResult{}, s.err
	}
	if r, ok := s.results[name]; ok {
		return r, nil
	}
	return egress.DNSResult{RCode: egress.RCodeNXDomain}, nil
}

func txt(v string) egress.DNSResult {
	return egress.DNSResult{RCode: egress.RCodeSuccess, Answers: []egress.Answer{{Type: "TXT", Value: v}}}
}
