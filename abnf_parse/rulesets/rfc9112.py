from abnf_parse.structures.ruleset import Ruleset

from abnf_parse.rulesets.rfc3986 import RFC3986_RULESET
from abnf_parse.rulesets.rfc9110 import RFC9110_RULESET


# NOTE: Only a subset has been implemented so far.


RFC9112_RULESET = Ruleset({
    'BWS': RFC9110_RULESET['BWS'],
    'OWS': RFC9110_RULESET['OWS'],
    'RWS': RFC9110_RULESET['RWS'],
    'absolute-path': RFC9110_RULESET['absolute-path'],
    'field-name': RFC9110_RULESET['field-name'],
    'field-value': RFC9110_RULESET['field-value'],
    'obs-text': RFC9110_RULESET['obs-text'],
    'quoted-string': RFC9110_RULESET['quoted-string'],
    'token': RFC9110_RULESET['token'],
    # transfer-coding
    'absolute-URI': RFC3986_RULESET['absolute-URI'],
    'authority': RFC3986_RULESET['authority'],
    'uri-host': RFC3986_RULESET['host'],
    'port': RFC3986_RULESET['port'],
    'query': RFC3986_RULESET['query']
}).update_from_source(
    source=(
        b'message-body = *OCTET\r\n'
        b'field-line = field-name ":" OWS field-value OWS\r\n'
        b'reason-phrase = 1*( HTAB / SP / VCHAR / obs-text)\r\n'
        b'status-code = 3DIGIT\r\n'
        b'HTTP-name = %s"HTTP"\r\n'
        b'HTTP-version = HTTP-name "/" DIGIT "." DIGIT\r\n'
        b'status-line = HTTP-version SP status-code SP [ reason-phrase ]\r\n'
        b'asterisk-form = "*"\r\n'
        b'authority-form = uri-host ":" port\r\n'
        b'absolute-form = absolute-URI\r\n'
        b'origin-form = absolute-path [ "?" query ]\r\n'
        b'request-target = origin-form / absolute-form / authority-form / asterisk-form\r\n'
        b'method = token\r\n'
        b'request-line = method SP request-target SP HTTP-version\r\n'
        b'start-line = request-line / status-line\r\n'
        b'HTTP-message = start-line CRLF *( field-line CRLF ) CRLF [ message-body ]\r\n'
    )
)
