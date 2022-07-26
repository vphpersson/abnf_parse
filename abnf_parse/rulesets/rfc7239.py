from abnf_parse.structures.ruleset import Ruleset

from abnf_parse.rulesets.rfc9110 import RFC9110_RULESET
from abnf_parse.rulesets.rfc3986 import RFC3986_RULESET

# NOTE: The RFC refers to RFC7230 for the definitions of "token" and "quoted-string",
# but it has been deprecated by RFC9110. The affected definitions are the same.

# NOTE: `Forwarded` is defined `Forwarded = 1#forwarded-element` in the RFC, but "# rules" do not seem to be officially
# defined.

RFC7239_RULESET = Ruleset({
    'token': RFC9110_RULESET['token'],
    'quoted-string': RFC9110_RULESET['quoted-string'],
    'OWS': RFC9110_RULESET['OWS'],
    'IPv4address': RFC3986_RULESET['IPv4address'],
    'IPv6address': RFC3986_RULESET['IPv6address']
}).update_from_source(
    source=(
        b'value = token / quoted-string\r\n'
        b'forwarded-pair = token "=" value\r\n'
        b'forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )\r\n'
        b'Forwarded = forwarded-element *( OWS "," OWS forwarded-element )\r\n'
        
        b'obfport = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")\r\n'
        b'port = 1*5DIGIT\r\n'
        b'node-port = port / obfport\r\n'
        b'obfnode = "_" 1*( ALPHA / DIGIT / "." / "_" / "-")\r\n'
        b'nodename = IPv4address / "[" IPv6address "]" / "unknown" / obfnode\r\n'
        b'node = nodename [ ":" node-port ]\r\n'
    )
)
