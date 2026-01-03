// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverhttps_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverhttps"
	"github.com/bassosimone/dnstest"
	"github.com/bassosimone/pkitest"
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

func TestIntegrationLocalServer(t *testing.T) {
	// 1. Create PKI for testing
	//
	// See https://github.com/bassosimone/pkitest
	pki := pkitest.MustNewPKI("testdata")
	certConfig := &pkitest.SelfSignedCertConfig{
		CommonName:   "example.com",
		DNSNames:     []string{"example.com"},
		IPAddrs:      []net.IP{net.IPv4(127, 0, 0, 1)},
		Organization: []string{"Example"},
	}
	cert := pki.MustNewCert(certConfig)
	clientConfig := &tls.Config{RootCAs: pki.CertPool()}

	// 2. Create DNS server for testing
	//
	// See https://github.com/bassosimone/dnstest
	dnsConfig := dnstest.NewHandlerConfig()
	dnsConfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.4.4"))
	dnsConfig.AddNetipAddr("dns.google", netip.MustParseAddr("8.8.8.8"))
	dnsHandler := dnstest.NewHandler(dnsConfig)
	srv := dnstest.MustNewHTTPSServer(&net.ListenConfig{}, "127.0.0.1:0", cert, dnsHandler)
	t.Cleanup(srv.Close)

	// Create an HTTP client
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: clientConfig}}

	// Finally, run the actual test
	run(t, httpClient, srv.URL())
}
