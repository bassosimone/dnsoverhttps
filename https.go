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
	"net/http"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/iox"
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

	// ObserveRawQuery is an optional hook called with a copy of the raw DNS query.
	ObserveRawQuery func([]byte)

	// ObserveRawResponse is an optional hook called with a copy of the raw DNS response.
	ObserveRawResponse func([]byte)
}

// NewTransport creates a new [*Transport].
func NewTransport(client Client, URL string) *Transport {
	return &Transport{Client: client, URL: URL}
}

// NewRequest serializes a DNS query message into an HTTP request.
//
// Returns the HTTP request ready for the round trip and the [*dns.Msg] query, which is
// required later on to properly validate the DNS response.
func NewRequest(ctx context.Context, query *dnscodec.Query, URL string) (*http.Request, *dns.Msg, error) {
	return NewRequestWithHook(ctx, query, URL, nil)
}

// NewRequestWithHook is like [NewRequest] but calls observeHook with a copy
// of the raw DNS query after serialization. If observeHook is nil, it is not called.
func NewRequestWithHook(ctx context.Context,
	query *dnscodec.Query, URL string, observeHook func([]byte)) (*http.Request, *dns.Msg, error) {
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
		return nil, nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, nil, err
	}
	if observeHook != nil {
		observeHook(bytes.Clone(rawQuery))
	}

	// 2. Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, URL, bytes.NewReader(rawQuery))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	return httpReq, queryMsg, nil
}

// Exchange sends a [*dnscodec.Query] and receives a [*dnscodec.Response].
func (dt *Transport) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. Prepare for exchanging
	httpReq, queryMsg, err := NewRequestWithHook(ctx, query, dt.URL, dt.ObserveRawQuery)
	if err != nil {
		return nil, err
	}

	// 2. Do the HTTP round trip
	httpResp, err := dt.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	// 3. Parse the results
	return ReadResponseWithHook(ctx, httpResp, queryMsg, dt.ObserveRawResponse)
}

// ReadResponseWithHook is like [ReadResponse] but calls observeHook with a copy
// of the raw DNS response after reading. If observeHook is nil, it is not called.
func ReadResponseWithHook(ctx context.Context,
	httpResp *http.Response, queryMsg *dns.Msg, observeHook func([]byte)) (*dnscodec.Response, error) {
	// 1. make sure we eventually close the body
	defer httpResp.Body.Close()

	// 2. Ensure that the response makes sense
	if httpResp.StatusCode != 200 {
		return nil, dnscodec.ErrServerMisbehaving
	}
	if httpResp.Header.Get("content-type") != "application/dns-message" {
		return nil, dnscodec.ErrServerMisbehaving
	}

	// 3. Limit response body to a reasonable size and read it
	//
	// - When the error is caused by the context, avoid ErrServerMisbehaving
	buff := &bytes.Buffer{}
	lockedWriter := iox.NewLockedWriteCloser(iox.NopWriteCloser(buff))
	reader := iox.LimitReadCloser(httpResp.Body, dnscodec.QueryMaxResponseSizeTCP)
	if _, err := iox.CopyContext(ctx, lockedWriter, reader); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, dnscodec.ErrServerMisbehaving
	}
	rawResp := buff.Bytes()
	if observeHook != nil {
		observeHook(bytes.Clone(rawResp))
	}

	// 4. Attempt to parse the raw response body
	respMsg := &dns.Msg{}
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, dnscodec.ErrServerMisbehaving
	}

	// 5. Parse the response and return the parsing result
	return dnscodec.ParseResponse(queryMsg, respMsg)
}

// ReadResponse reads and validates a DNS response as the response for the given query.
//
// Because this function reads the whole response body, it closes it when done.
//
// The context is used to interrupt reading the round trip or reading the response body.
func ReadResponse(ctx context.Context, resp *http.Response, query *dns.Msg) (*dnscodec.Response, error) {
	return ReadResponseWithHook(ctx, resp, query, nil)
}
