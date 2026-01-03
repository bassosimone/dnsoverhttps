//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsoverhttps.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/dohttps.go
//

package dnsoverhttps

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
)

// Client abstracts over [*http.Client].
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Transport is a DNS-over-HTTPS transport.
//
// Construct using [NewTransport].
type Transport struct {
	// Client is the [Client] to use to exchange a query for a response.
	//
	// Set by [NewTransport] to the user-provided value.
	Client Client

	// URL is the server URL to use to exchange a query for a response.
	//
	// Set by [NewTransport] to the user-provided value.
	URL string
}

// NewTransport creates a new [*Transport].
func NewTransport(client Client, URL string) *Transport {
	return &Transport{Client: client, URL: URL}
}

// Exchange sends a [*dnscodec.Query] and receives a [*dnscodec.Response].
func (dt *Transport) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. Mutate and serialize the query
	//
	// For DoH, by default we leave the query ID to zero, which
	// is what the RFC suggests to do.
	query = query.Clone()
	query.Flags |= dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	query.ID = 0
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 2. Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, dt.URL, bytes.NewReader(rawQuery))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")

	// 3. Do the HTTP round trip
	httpResp, err := dt.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// 4. Ensure that the response makes sense
	if httpResp.StatusCode != 200 {
		return nil, dnscodec.ErrServerMisbehaving
	}
	if httpResp.Header.Get("content-type") != "application/dns-message" {
		return nil, dnscodec.ErrServerMisbehaving
	}

	// 5. Limit response body to a reasonable size and read it
	reader := io.LimitReader(httpResp.Body, dnscodec.QueryMaxResponseSizeTCP)
	rawResp, err := io.ReadAll(reader)
	if err != nil {
		return nil, dnscodec.ErrServerMisbehaving
	}

	// 6. Attempt to parse the raw response body
	respMsg := &dns.Msg{}
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}

	// 7. Parse the response and return the parsing result
	return dnscodec.ParseResponse(queryMsg, respMsg)
}
