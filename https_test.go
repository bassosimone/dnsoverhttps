// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverhttps_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverhttps"
	"github.com/bassosimone/httptestx"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run exchanges a query for dns.google with the given client and URL and
// verifies that the response is the one we expect.
func run(t *testing.T, client dnsoverhttps.Client, URL string) {
	ctx := context.Background()
	dt := dnsoverhttps.NewTransport(client, URL)
	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(ctx, query)
	require.NoError(t, err)
	addrs, err := resp.RecordsA()
	require.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestIntegrationHTTP2(t *testing.T) {
	run(t, http.DefaultClient, "https://dns.google/dns-query")
}

func TestIntegrationHTTP3(t *testing.T) {
	httpClient := &http.Client{Transport: &http3.Transport{}}
	run(t, httpClient, "https://dns.google/dns-query")
}

// hasPaddingOption returns whether the message includes EDNS0 padding.
func hasPaddingOption(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if _, ok := option.(*dns.EDNS0_PADDING); ok {
			return true
		}
	}
	return false
}

// buildDNSResponse returns a packed reply with a single A record.
func buildDNSResponse(t *testing.T, query *dns.Msg) []byte {
	t.Helper()

	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    1,
		},
		A: []byte{8, 8, 8, 8},
	})
	rawResp, err := resp.Pack()
	require.NoError(t, err)

	return rawResp
}

func TestExchangeClientDoError(t *testing.T) {
	wantErr := errors.New("mocked error")
	client := &httptestx.FuncClient{DoFunc: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	dt := dnsoverhttps.NewTransport(client, "https://example.com/dns-query")

	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.Error(t, err)
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, resp)
}

func TestExchangeDoesNotMutateQuery(t *testing.T) {
	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	query.Flags = dnscodec.QueryFlagDNSSec
	query.ID = 1234
	query.MaxSize = dnscodec.QueryMaxResponseSizeUDP
	orig := *query

	wantErr := errors.New("mocked error")
	client := &httptestx.FuncClient{DoFunc: func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}}
	dt := dnsoverhttps.NewTransport(client, "https://example.com/dns-query")
	resp, err := dt.Exchange(context.Background(), query)

	require.Error(t, err)
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, resp)
	assert.Equal(t, orig, *query)
}

func TestExchangeRequestCreationError(t *testing.T) {
	dt := dnsoverhttps.NewTransport(http.DefaultClient, "\t")

	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestExchangeQueryNewMsgError(t *testing.T) {
	dt := dnsoverhttps.NewTransport(http.DefaultClient, "https://example.com/dns-query")

	query := dnscodec.NewQuery("\t", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestExchangeQueryPackError(t *testing.T) {
	dt := dnsoverhttps.NewTransport(http.DefaultClient, "https://example.com/dns-query")

	tooLongLabel := strings.Repeat("a", 64)
	query := dnscodec.NewQuery(tooLongLabel+".example.com", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.Error(t, err)
	require.Nil(t, resp)
}

func TestExchangeRequestShape(t *testing.T) {
	wantErr := errors.New("mocked error")
	var gotReq *http.Request
	client := &httptestx.FuncClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		gotReq = req
		return nil, wantErr
	}}
	dt := dnsoverhttps.NewTransport(client, "https://example.com/dns-query")

	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.Error(t, err)
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, resp)
	require.NotNil(t, gotReq)
	assert.Equal(t, http.MethodPost, gotReq.Method)
	assert.Equal(t, "application/dns-message", gotReq.Header.Get("Content-Type"))
	assert.Equal(t, "https://example.com/dns-query", gotReq.URL.String())

	rawQuery, err := io.ReadAll(gotReq.Body)
	require.NoError(t, err)
	require.NoError(t, gotReq.Body.Close())

	queryMsg := &dns.Msg{}
	require.NoError(t, queryMsg.Unpack(rawQuery))
	assert.Equal(t, uint16(0), queryMsg.Id)
	assert.NotNil(t, queryMsg.IsEdns0())
	assert.Equal(t, uint16(dnscodec.QueryMaxResponseSizeTCP), queryMsg.IsEdns0().UDPSize())
	assert.True(t, queryMsg.IsEdns0().Do())
	assert.True(t, hasPaddingOption(queryMsg))
}

func TestExchangeObserveRawQuery(t *testing.T) {
	rawQueryCh := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())

		rawQueryCh <- append([]byte{}, rawQuery...)
		queryMsg := &dns.Msg{}
		require.NoError(t, queryMsg.Unpack(rawQuery))

		rawResp := buildDNSResponse(t, queryMsg)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(rawResp)
		require.NoError(t, err)
	}))
	defer srv.Close()

	var hookQuery []byte
	dt := dnsoverhttps.NewTransport(srv.Client(), srv.URL)
	dt.ObserveRawQuery = func(p []byte) {
		hookQuery = append([]byte{}, p...)
		if len(p) > 0 {
			p[0] ^= 0xff // mutate to verify we've got a copy
		}
	}

	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, <-rawQueryCh, hookQuery)
}

func TestExchangeObserveRawResponse(t *testing.T) {
	rawRespCh := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())

		queryMsg := &dns.Msg{}
		require.NoError(t, queryMsg.Unpack(rawQuery))

		rawResp := buildDNSResponse(t, queryMsg)
		rawRespCh <- append([]byte{}, rawResp...)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(rawResp)
		require.NoError(t, err)
	}))
	defer srv.Close()

	var hookResp []byte
	dt := dnsoverhttps.NewTransport(srv.Client(), srv.URL)
	dt.ObserveRawResponse = func(p []byte) {
		hookResp = append([]byte{}, p...)
		if len(p) > 0 {
			p[0] ^= 0xff // mutate to verify we've got a copy
		}
	}

	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(context.Background(), query)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, <-rawRespCh, hookResp)
}

func TestExchangeUsesContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var gotCtx context.Context
	client := &httptestx.FuncClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		gotCtx = req.Context()
		return nil, req.Context().Err()
	}}
	dt := dnsoverhttps.NewTransport(client, "https://example.com/dns-query")

	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resp, err := dt.Exchange(ctx, query)

	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, resp)
	require.NotNil(t, gotCtx)
	require.ErrorIs(t, gotCtx.Err(), context.Canceled)
}

func TestExchangeServerResponses(t *testing.T) {

	type testCase struct {
		// name is the subtest name.
		name string

		// handler serves the DoH response for the incoming query.
		handler func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg)

		// wantErr is the expected error (nil on success).
		wantErr error

		// checkReply validates the parsed response on success.
		checkReply func(t *testing.T, resp *dnscodec.Response)
	}

	// makeServer spins up a test server and decodes incoming DNS queries.
	makeServer := func(t *testing.T, handler func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg)) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawQuery, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, r.Body.Close())

			query := &dns.Msg{}
			require.NoError(t, query.Unpack(rawQuery))

			handler(t, w, r, query)
		}))
	}

	// writeDNSResponse serializes and writes a DNS response with the right headers.
	writeDNSResponse := func(t *testing.T, w http.ResponseWriter, resp *dns.Msg) {
		t.Helper()
		rawResp, err := resp.Pack()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(rawResp)
		require.NoError(t, err)
	}

	testCases := []testCase{
		{
			name: "non-200 status",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				w.Header().Set("Content-Type", "application/dns-message")
				w.WriteHeader(http.StatusTeapot)
			},
			wantErr: dnscodec.ErrServerMisbehaving,
		},

		{
			name: "wrong content-type",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				rawResp, err := resp.Pack()
				require.NoError(t, err)
				_, err = w.Write(rawResp)
				require.NoError(t, err)
			},
			wantErr: dnscodec.ErrServerMisbehaving,
		},

		{
			name: "malformed response body",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				w.Header().Set("Content-Type", "application/dns-message")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("not a dns message"))
				require.NoError(t, err)
			},
			wantErr: dnscodec.ErrServerMisbehaving,
		},

		{
			name: "short body read error",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				w.Header().Set("Content-Type", "application/dns-message")
				w.Header().Set("Content-Length", "10")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte{0x01, 0x02})
				require.NoError(t, err)
			},
			wantErr: dnscodec.ErrServerMisbehaving,
		},

		{
			name: "invalid response for query",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				resp.Id = query.Id + 1
				writeDNSResponse(t, w, resp)
			},
			wantErr: dnscodec.ErrInvalidResponse,
		},

		{
			name: "oversized response body",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				w.Header().Set("Content-Type", "application/dns-message")
				w.WriteHeader(http.StatusOK)
				oversized := make([]byte, dnscodec.QueryMaxResponseSizeTCP+1)
				_, err := w.Write(oversized)
				require.NoError(t, err)
			},
			wantErr: dnscodec.ErrInvalidResponse,
		},

		{
			name: "valid response",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, query *dns.Msg) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   query.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    3600,
					},
					A: []byte{8, 8, 8, 8},
				})
				writeDNSResponse(t, w, resp)
			},
			checkReply: func(t *testing.T, resp *dnscodec.Response) {
				addrs, err := resp.RecordsA()
				require.NoError(t, err)
				assert.Equal(t, []string{"8.8.8.8"}, addrs)
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			srv := makeServer(t, tt.handler)
			defer srv.Close()

			dt := dnsoverhttps.NewTransport(srv.Client(), srv.URL)
			query := dnscodec.NewQuery("dns.google", dns.TypeA)
			resp, err := dt.Exchange(context.Background(), query)

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			if tt.checkReply != nil {
				tt.checkReply(t, resp)
			}
		})
	}
}
