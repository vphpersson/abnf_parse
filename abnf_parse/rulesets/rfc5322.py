from abnf_parse.structures.ruleset import Ruleset

# NOTE: Only a subset has been implemented so far.

RFC5322_RULESET = Ruleset.from_source(
    source=(
        b'obs-FWS = 1*WSP *(CRLF 1*WSP)\r\n'
        b'obs-NO-WS-CTL = %d1-8 / %d11 / %d12 / %d14-31 / %d127\r\n'
        b'obs-ctext = obs-NO-WS-CTL\r\n'
        b'obs-qtext = obs-NO-WS-CTL\r\n'
        b'obs-qp = "\\" (%d0 / obs-NO-WS-CTL / LF / CR)\r\n'

        b'quoted-pair = ("\\" (VCHAR / WSP)) / obs-qp\r\n'
        
        b'obs-dtext = obs-NO-WS-CTL / quoted-pair\r\n'

        b'FWS = ([*WSP CRLF] 1*WSP) / obs-FWS\r\n'
        b'ctext = %d33-39 / %d42-91 / %d93-126 / obs-ctext\r\n'
        b'ccontent = ctext / quoted-pair / comment\r\n'
        b'comment = "(" *([FWS] ccontent) [FWS] ")"\r\n'
        b'CFWS = (1*([FWS] comment) [FWS]) / FWS\r\n'
        
        b'atext = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "\'" / "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"\r\n'
        b'atom = [CFWS] 1*atext [CFWS]\r\n'
        b'dot-atom-text = 1*atext *("." 1*atext)\r\n'
        b'dot-atom = [CFWS] dot-atom-text [CFWS]\r\n'

        b'qtext = %d33 / %d35-91 /  %d93-126 / obs-qtext\r\n'
        b'qcontent =   qtext / quoted-pair\r\n'
        b'quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]\r\n'
        
        b'word = atom / quoted-string\r\n'
        b'obs-local-part = word *("." word)\r\n'
        b'obs-domain = atom *("." atom)\r\n'

        b'dtext = %d33-90 / %d94-126 / obs-dtext\r\n'
        b'domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]\r\n'
        b'domain =  dot-atom / domain-literal / obs-domain\r\n'
        b'local-part = dot-atom / quoted-string / obs-local-part\r\n'
        b'addr-spec = local-part "@" domain\r\n'

        b'obs-id-right = domain\r\n'
        b'obs-id-left = local-part\r\n'

        b'no-fold-literal = "[" *dtext "]"\r\n'
        b'id-right = dot-atom-text / no-fold-literal / obs-id-right\r\n'
        b'id-left = dot-atom-text / obs-id-left\r\n'
        b'msg-id = [CFWS] "<" id-left "@" id-right ">" [CFWS]\r\n'

        b'obs-day-of-week = [CFWS] day-name [CFWS]\r\n'
        b'obs-day = [CFWS] 1*2DIGIT [CFWS]\r\n'
        b'obs-year = [CFWS] 2*DIGIT [CFWS]\r\n'
        b'obs-hour = [CFWS] 2DIGIT [CFWS]\r\n'
        b'obs-minute = [CFWS] 2DIGIT [CFWS]\r\n'
        b'obs-second = [CFWS] 2DIGIT [CFWS]\r\n'
        b'obs-zone = "UT" / "GMT" / "EST" / "EDT" / "CST" / "CDT" / "MST" / "MDT" / "PST" / "PDT" / %d65-73 / %d75-90 / %d97-105 / %d107-122\r\n'
        
        b'zone = (FWS ( "+" / "-" ) 4DIGIT) / obs-zone\r\n'
        b'second = 2DIGIT / obs-second\r\n'
        b'minute = 2DIGIT / obs-minute\r\n'
        b'hour = 2DIGIT / obs-hour\r\n'
        b'time-of-day = hour ":" minute [ ":" second ]\r\n'
        b'time = time-of-day zone\r\n'
        b'year = (FWS 4*DIGIT FWS) / obs-year\r\n'
        b'month = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" / "Jul" / "Aug" / "Sep" / "Oct" / "Nov" / "Dec"\r\n'
        b'day = ([FWS] 1*2DIGIT FWS) / obs-day\r\n'
        b'date = day month year\r\n'
        b'day-name = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"\r\n'
        b'day-of-week = ([FWS] day-name) / obs-day-of-week\r\n'
        b'date-time = [ day-of-week "," ] date time [CFWS]\r\n'
    )
)
