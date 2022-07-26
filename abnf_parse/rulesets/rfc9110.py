from abnf_parse.structures.ruleset import Ruleset

from abnf_parse.rulesets.rfc3986 import RFC3986_RULESET

# NOTE: Only a subset has been implemented so far.

RFC9110_RULESET = Ruleset({
    'segment': RFC3986_RULESET['segment'],
    'uri-host': RFC3986_RULESET['host'],
    'port': RFC3986_RULESET['port']
}).update_from_source(
    source=(
        b'Host = uri-host [ ":" port ]\r\n'
        b'OWS = *( SP / HTAB )\r\n'
        b'RWS = 1*( SP / HTAB )\r\n'
        b'BWS = OWS\r\n'
        b'obs-text = %x80-FF\r\n'
        b'quoted-pair    = "\\" ( HTAB / SP / VCHAR / obs-text )\r\n'
        b'qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text\r\n'
        b'quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE\r\n'
        b'field-vchar = VCHAR / obs-text\r\n'
        b'field-content = field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]\r\n'
        b'field-value = *field-content\r\n'
        b'tchar = "!" / "#" / "$" / "%" / "&" / "\'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA\r\n'
        b'token = 1*tchar\r\n'
        b'field-name = token\r\n'
        b'absolute-path = 1*( "/" segment )\r\n'
        b'RWS = 1*( SP / HTAB )\r\n'
        b'obs-text = %x80-FF\r\n'
    )
)