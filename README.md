# Copper

This tool will attempt to discover active hosts using the following:
- ICMP Ping.
- Checking TCP ports until it finds an open one.

If a method succeeds, the host is marked as active and not touched again.


## Usage

```
  copper [flags]

Flags:
  -f, --file string        File with scope to check (default "scope.txt")
  -h, --help               help for copper
  -i, --icmp-timeout int   ICMP timeout in milliseconds (default 1000)
  -T, --tcp-ports int      Number of TCP ports to check (default 100)
  -t, --tcp-timeout int    TCP timeout in milliseconds (default 1000)
  -v, --verbose            Print active hosts as they are found
```