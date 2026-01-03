// SPDX-License-Identifier: GPL-3.0-or-later

package dnsoverhttps_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverhttps"
	"github.com/bassosimone/dnstest"
	"github.com/bassosimone/pkitest"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
)

func Example_withLocalServer() {
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
	defer srv.Close()

	// 3. Create the DNS transport
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: clientConfig}}
	dt := dnsoverhttps.NewTransport(httpClient, srv.URL())

	// 4. Create the query
	query := dnscodec.NewQuery("dns.google", dns.TypeA)

	// 5. Exchange with the server
	ctx := context.Background()
	resp := runtimex.PanicOnError1(dt.Exchange(ctx, query))

	// 6. Obtain the A records from the response
	addrs := runtimex.PanicOnError1(resp.RecordsA())

	// 7. Sort and print the addresses
	slices.Sort(addrs)
	fmt.Printf("%+v\n", addrs)

	// Output:
	// [8.8.4.4 8.8.8.8]
}
