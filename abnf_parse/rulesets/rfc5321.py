from abnf_parse.structures.ruleset import Ruleset

from abnf_parse.rulesets.rfc3986 import RFC3986_RULESET
from abnf_parse.rulesets.rfc5322 import RFC5322_RULESET

# NOTE: Only a subset has been implemented so far.

RFC5321_RULESET: Ruleset = Ruleset({
    'IPv4-address-literal': RFC3986_RULESET['IPv4address'],
    'IPv6-addr': RFC3986_RULESET['IPv6address'],
    'atext': RFC5322_RULESET['atext'],
    'msg-id': RFC5322_RULESET['msg-id'],
    'FWS': RFC5322_RULESET['FWS'],
    'CFWS': RFC5322_RULESET['CFWS'],
}).update_from_source(
    source=(
        b'zone = (FWS ( "+" / "-" ) 4DIGIT)\r\n'
        b'second = 2DIGIT\r\n'
        b'minute = 2DIGIT\r\n'
        b'hour = 2DIGIT\r\n'
        b'time-of-day = hour ":" minute [ ":" second ]\r\n'
        b'time = time-of-day zone\r\n'
        b'year = (FWS 4*DIGIT FWS)\r\n'
        b'month = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" / "Jul" / "Aug" / "Sep" / "Oct" / "Nov" / "Dec"\r\n'
        b'day = ([FWS] 1*2DIGIT FWS)\r\n'
        b'date = day month year\r\n'
        b'day-name = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"\r\n'
        b'day-of-week = ([FWS] day-name)\r\n'
        b'date-time = [ day-of-week "," ] date time [CFWS]\r\n'
        
        b'Let-dig = ALPHA / DIGIT\r\n'
        b'Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig\r\n'
        b'dcontent = %d33-90 / %d94-126\r\n'
        b'Standardized-tag = Ldh-str\r\n'
        b'General-address-literal = Standardized-tag ":" 1*dcontent\r\n'
        b'IPv6-address-literal = "IPv6" IPv6-addr\r\n'

        b'Atom = 1*atext\r\n'
        b'qtextSMTP = %d32-33 / %d35-91 / %d93-126\r\n'
        b'quoted-pairSMTP = %d92 %d32-126\r\n'
        b'QcontentSMTP = qtextSMTP / quoted-pairSMTP\r\n'
        b'Quoted-string = DQUOTE *QcontentSMTP DQUOTE\r\n'
        b'String = Atom / Quoted-string\r\n'
        b'Dot-string = Atom *("."  Atom)\r\n'
        b'Local-part = Dot-string / Quoted-string\r\n'
        b'address-literal  = "[" ( IPv4-address-literal / IPv6-address-literal / General-address-literal ) "]"\r\n'
        b'Mailbox = Local-part "@" ( Domain / address-literal )\r\n'
        b'sub-domain = Let-dig [Ldh-str]\r\n'
        b'Domain = sub-domain *("." sub-domain)\r\n'
        b'Argument = Atom\r\n'
        b'Keyword = Ldh-str\r\n'
        b'esmtp-value = 1*(%d33-60 / %d62-126)\r\n'
        b'esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")\r\n'
        b'esmtp-param = esmtp-keyword ["=" esmtp-value]\r\n'
        b'Rcpt-parameters = esmtp-param *(SP esmtp-param)\r\n'
        b'Mail-parameters = esmtp-param *(SP esmtp-param)\r\n'
        b'At-domain = "@" Domain\r\n'
        b'A-d-l = At-domain *( "," At-domain )\r\n'
        b'Path = "<" [ A-d-l ":" ] Mailbox ">"\r\n'
        b'Forward-path = Path \r\n'
        b'Reverse-path = Path / "<>"\r\n'
        
        b'Attdl-Protocol = Atom\r\n'
        b'Protocol = "ESMTP" / "SMTP" / Attdl-Protocol\r\n'
        b'Addtl-Link = Atom\r\n'
        b'Link = "TCP" / Addtl-Link\r\n'
        b'Additional-Registered-Clauses = CFWS Atom FWS String\r\n'
        b'For = CFWS "FOR" FWS ( Path / Mailbox )\r\n'
        b'ID = CFWS "ID" FWS ( Atom / msg-id )\r\n'
        b'With = CFWS "WITH" FWS Protocol\r\n'
        b'Via = CFWS "VIA" FWS Link\r\n'
        b'Opt-info = [Via] [With] [ID] [For] [Additional-Registered-Clauses]\r\n'
        b'TCP-info = address-literal / ( Domain FWS address-literal )\r\n'
        # NOTE: `Domain` was moved so that `TCP-info` can get matched; otherwise `TCP-info` will match `CFWS` when
        # using the `Stamp` rule.
        b'Extended-Domain  = ( Domain FWS "(" TCP-info ")" ) / ( address-literal FWS "(" TCP-info ")" ) / Domain\r\n'
        b'By-domain = CFWS "BY" FWS Extended-Domain\r\n'
        b'From-domain = "FROM" FWS Extended-Domain\r\n'
        b'Stamp = From-domain By-domain Opt-info [CFWS] ";" FWS date-time\r\n'
        b'Time-stamp-line = "Received:" FWS Stamp\r\n'
        b'Return-path-line = "Return-Path:" FWS Reverse-path\r\n'
    )
)

RFC5321_LENIENT_RULESET: Ruleset = Ruleset({
    'IPv4-address-literal': RFC3986_RULESET['IPv4address'],
    'IPv6-addr': RFC3986_RULESET['IPv6address'],
    'atext': RFC5322_RULESET['atext'],
    'msg-id': RFC5322_RULESET['msg-id'],
    'FWS': RFC5322_RULESET['FWS'],
    'CFWS': RFC5322_RULESET['CFWS'],
}).update_from_source(
    source=(
        b'zone = (FWS ( "+" / "-" ) 4DIGIT)\r\n'
        b'second = 2DIGIT\r\n'
        b'minute = 2DIGIT\r\n'
        b'hour = 2DIGIT\r\n'
        b'time-of-day = hour ":" minute [ ":" second ]\r\n'
        b'time = time-of-day zone\r\n'
        b'year = (FWS 4*DIGIT FWS)\r\n'
        b'month = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" / "Jul" / "Aug" / "Sep" / "Oct" / "Nov" / "Dec"\r\n'
        b'day = ([FWS] 1*2DIGIT FWS)\r\n'
        b'date = day month year\r\n'
        b'day-name = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"\r\n'
        b'day-of-week = ([FWS] day-name)\r\n'
        b'date-time = [ day-of-week "," ] date time [CFWS]\r\n'

        b'Let-dig = ALPHA / DIGIT\r\n'
        b'Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig\r\n'
        b'dcontent = %d33-90 / %d94-126\r\n'
        b'Standardized-tag = Ldh-str\r\n'
        b'General-address-literal = Standardized-tag ":" 1*dcontent\r\n'
        b'IPv6-address-literal = "IPv6" IPv6-addr / IPv6-addr\r\n'

        b'Atom = 1*atext\r\n'
        b'qtextSMTP = %d32-33 / %d35-91 / %d93-126\r\n'
        b'quoted-pairSMTP = %d92 %d32-126\r\n'
        b'QcontentSMTP = qtextSMTP / quoted-pairSMTP\r\n'
        b'Quoted-string = DQUOTE *QcontentSMTP DQUOTE\r\n'
        b'String = Atom / Quoted-string\r\n'
        b'Dot-string = Atom *("."  Atom)\r\n'
        b'Local-part = Dot-string / Quoted-string\r\n'
        b'address-literal  = ( "[" ( IPv4-address-literal / IPv6-address-literal / General-address-literal ) "]" ) / IPv4-address-literal / IPv6-address-literal / General-address-literal\r\n'
        b'Mailbox = Local-part "@" ( Domain / address-literal )\r\n'
        b'sub-domain = Let-dig [Ldh-str]\r\n'
        b'Domain = sub-domain *("." sub-domain)\r\n'
        b'Argument = Atom\r\n'
        b'Keyword = Ldh-str\r\n'
        b'esmtp-value = 1*(%d33-60 / %d62-126)\r\n'
        b'esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")\r\n'
        b'esmtp-param = esmtp-keyword ["=" esmtp-value]\r\n'
        b'Rcpt-parameters = esmtp-param *(SP esmtp-param)\r\n'
        b'Mail-parameters = esmtp-param *(SP esmtp-param)\r\n'
        b'At-domain = "@" Domain\r\n'
        b'A-d-l = At-domain *( "," At-domain )\r\n'
        b'Path = "<" [ A-d-l ":" ] Mailbox ">"\r\n'
        b'Forward-path = Path \r\n'
        b'Reverse-path = Path / "<>"\r\n'

        b'Attdl-Protocol = Atom\r\n'
        b'Protocol = "ESMTP" / "SMTP" / Attdl-Protocol\r\n'
        b'Addtl-Link = Atom\r\n'
        b'Link = "TCP" / Addtl-Link\r\n'
        b'Additional-Registered-Clauses = CFWS Atom FWS String\r\n'
        b'For = CFWS "FOR" FWS ( Path / Mailbox )\r\n'
        b'ID = CFWS "ID" FWS ( Atom / msg-id )\r\n'
        b'With = CFWS "WITH" FWS Protocol\r\n'
        b'Via = CFWS "VIA" FWS Link\r\n'
        b'Opt-info = [Via] [With] [ID] [For] [Additional-Registered-Clauses]\r\n'
        b'TCP-info = address-literal / ( Domain FWS address-literal )\r\n'
        # NOTE: `Domain` was moved so that `TCP-info` can get matched; otherwise `TCP-info` will match `CFWS` when
        # using the `Stamp` rule.
        b'Extended-Domain  = ( Domain FWS "(" TCP-info ")" ) / ( address-literal FWS "(" TCP-info ")" ) / Domain\r\n'
        b'By-domain = CFWS "BY" FWS Extended-Domain\r\n'
        b'From-domain = "FROM" FWS Extended-Domain\r\n'
        b'Stamp = From-domain By-domain Opt-info [CFWS] ";" FWS date-time\r\n'
        b'Time-stamp-line = "Received:" FWS Stamp\r\n'
        b'Return-path-line = "Return-Path:" FWS Reverse-path\r\n'
    )
)
