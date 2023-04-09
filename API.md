# neosocksd API Reference

Version: dev

## Index

- [RESTful API](#restful-api)
- [Ruleset Callbacks](#ruleset-callbacks)
- [Lua API](#lua-api)

## RESTful API

*The RESTful API server runs HTTP/1.0*

### Healthy Check

Check server liveness.

```
Path: /healthy
Method: Any
Reply: HTTP 200
```

### Server Statistics

Calculate server statistics since the last call.

```
Path: /stats
Method: GET
Reply: HTTP 200
```

### Ruleset Invoke

Run the posted script.

```
Path: /ruleset/invoke
Method: POST
Content: Lua script
Reply: HTTP 200, HTTP 405, HTTP 500
```

### Ruleset Update

Replace ruleset with the posted script.

```
Path: /ruleset/update
Method: POST
Content: Lua ruleset script
Reply: HTTP 200, HTTP 405, HTTP 500
```

### Ruleset GC

Trigger a full GC.

```
Path: /ruleset/gc
Method: POST
Content: None
Reply: HTTP 200, HTTP 405
```

## Ruleset Callbacks

### ruleset.resolve

**Defination**

```Lua
ruleset.resolve(domain)
```

**Brief**

Process a host name request. Specifically:
- Any HTTP CONNECT
- SOCKS5 with host name (a.k.a. "socks5h")
- Any SOCKS4A

**Params**

    domain: full qualified domain name and port, like "www.example.org:80"

**Returns**

    addr: replace the request
    addr, proxy: forward the request through another neosocksd
    addr, proxyN, ..., proxy1: forward the request through proxy chain
    nil: reject the request

### ruleset.route

**Defination**

```Lua
ruleset.route(addr)
```

**Brief**

Process an IPv4 request. Specifically:
- SOCKS5 with IPv4 address
- Any SOCKS4

**Params**

    addr: address and port, like "8.8.8.8:53"

**Returns**

    Same as ruleset.resolve

### ruleset.route6

**Defination**

```Lua
ruleset.route6(addr)
```

**Brief**

Process an IPv6 request. Specifically:

- SOCKS5 with IPv6 address

**Params**

    addr: address and port, like "8.8.8.8:53"

**Returns**

    Same as ruleset.resolve

### ruleset.tick

**Defination**

```Lua
ruleset.tick(now)
```

**Brief**

Periodic timer callback.

**Params**

    now: current timestamp in seconds

**Returns**

    Ignored


## Lua API

### neosocksd.invoke

### neosocksd.resolve

### neosocksd.parse_ipv4

### neosocksd.parse_ipv6

### neosocksd.setinterval
