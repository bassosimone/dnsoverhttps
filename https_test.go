// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverhttps_test

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverhttps"
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
