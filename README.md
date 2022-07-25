# abnf_parse

An ABNF parsing library.

## Usage

### Provide your own rules

```python
from abnf_parse.rulesets import Ruleset

ipv6_ruleset = Ruleset.from_source(
    source=(
        b'dec-octet = "25" %x30-35 / "2" %x30-34 DIGIT / "1" 2DIGIT / %x31-39 DIGIT / DIGIT\r\n'
        b'IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet\r\n'
        b'h16 = 1*4HEXDIG\r\n'
        b'ls32 = ( h16 ":" h16 ) / IPv4address\r\n'
        b'IPv6address = 6( h16 ":" ) ls32 / "::" 5( h16 ":" ) ls32 / [ h16 ] "::" 4( h16 ":" ) ls32 / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32 / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32 / [ *3( h16 ":" ) h16 ] "::" h16 ":" ls32 / [ *4( h16 ":" ) h16 ] "::" ls32 / [ *5( h16 ":" ) h16 ] "::" h16 / [ *6( h16 ":" ) h16 ] "::"\r\n'
    )
)

candidates = [
    b'2001:DB8:CAFE::17',
    b'192.168.0.1',
    b'2001:0db8:0000:0000:0000:ff00:0042:8329'
]

for candidate in candidates:
    match = ipv6_ruleset['IPv6address'].evaluate(source=candidate)
    print(f'{candidate.decode()} is{" not" if not match else ""} an IPv6 address.')
```

**Output**
```
2001:DB8:CAFE::17 is an IPv6 address.
192.168.0.1 is not an IPv6 address.
2001:0db8:0000:0000:0000:ff00:0042:8329 is an IPv6 address.
```

### Use an existing rule

```python
from abnf_parse.rulesets.rfc9112 import RFC9112_RULESET

start_line_match = RFC9112_RULESET['start-line'].evaluate(source=b'HTTP/1.1 200 OK')

print(
    f'The start line is a "{start_line_match.children[0].name}".\n'
    f'The version is "{next(start_line_match.search(name="HTTP-version"))}".'
)
```

**Output**
```
The start line is a "status-line".
The version is "HTTP/1.1".
```
