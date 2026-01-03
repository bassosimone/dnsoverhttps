# Golang DNS-over-HTTPS transport

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/dnsoverhttps)](https://pkg.go.dev/github.com/bassosimone/dnsoverhttps) [![Build Status](https://github.com/bassosimone/dnsoverhttps/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/dnsoverhttps/actions) [![codecov](https://codecov.io/gh/bassosimone/dnsoverhttps/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/dnsoverhttps)

The `dnsoverhttps` Go package implements a DNS-over-HTTPS transport with a
small API suited for measurements and testing.

Basic usage is like:

```Go
import (
	"context"
	"log"
	"net/http"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnsoverhttps"
	"github.com/miekg/dns"
)

// 1. create the DNS-over-HTTPS transport
client := &http.Client{}
dt := dnsoverhttps.NewTransport(client, "https://dns.google/dns-query")

// 2. create and send a query
query := dnscodec.NewQuery("dns.google", dns.TypeA)
resp, err := dt.Exchange(context.Background(), query)
if err != nil {
	log.Fatal(err)
}
```

## Features

- **DNS-over-HTTPS:** Implements POST-based DNS-over-HTTPS.

- **Small API:** One transport with a single Exchange method.

- **Deterministic queries:** Mutates queries for transport needs while
  keeping the caller's query intact.

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/dnsoverhttps
```

## Development

To run the tests:

```sh
go test -v .
```

To measure test coverage:

```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## History

Adapted from [rbmk-project/rbmk](https://github.com/rbmk-project/rbmk/tree/v0.17.0).
