# pepbut

![pepbut](https://user-images.githubusercontent.com/52814/36644695-048da318-1a13-11e8-9dd2-5869434e62b8.gif)

pepbut is [Wobscale](https://github.com/wobscale)'s authoritative DNS server and record update API / console, written in Rust.

It is in development and should not be used in production.

Some of the implementation is inspired by [TRust-DNS](https://github.com/bluejekyll/trust-dns).

pepbut requires Rust 1.26 or later to build (`conservative_impl_trait` stabilization).

## Goals and non-goals

Goals:

* Fast (de)serialization of zone files (no parsers!)
* CNAME flattening (defining CNAMEs at the root of zones, but resolving and returning A/AAAA records)
* Wildcard record support
* An API for updating records
* A web interface that uses the API to update records

Non-goals:

* Recursive resolving (notwithstanding CNAME flattening)
* [DNSSEC](https://sockpuppet.org/blog/2015/01/15/against-dnssec/)
* Use as a secondary DNS server
* Zone transfers (AXFR)
