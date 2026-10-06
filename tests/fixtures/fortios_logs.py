"""Realistic FortiOS 7.x test fixtures spanning DPI, UTM, and traffic logs."""

SAMPLE_TRAFFIC_DENY = (
    'eventtime=1791271928296821451 tz="+0530" logid="0000000013" type="traffic" '
    'subtype="forward" level="notice" vd="root" srcip=10.0.14.120 srcport=57330 '
    'srcintf="port1" srcintfrole="lan" dstip=185.45.192.135 dstport=80 dstintf="port5" '
    'dstintfrole="wan" srccountry="Reserved" dstcountry="Netherlands" sessionid=1125626405 '
    'proto=6 action="deny" policyid=0 policytype="policy" service="HTTP" trandisp="noop" '
    'appcat="unscanned" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 crscore=30 '
    'craction=131072 crlevel="high"'
)

SAMPLE_WEBFILTER_BLOCKED = (
    'eventtime=1791271940626756995 tz="+0530" logid="0316013056" type="utm" '
    'subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=5 '
    'sessionid=1125640633 srcip=172.16.10.11 srcport=63223 dstip=142.251.222.174 '
    'dstport=443 proto=6 service="HTTPS" hostname="play.google.com" profile="Web-EMP" '
    'action="blocked" reqtype="direct" url="https://play.google.com/" sentbyte=1827 '
    'rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy"'
)

SAMPLE_IPS_NONBLOCKED_EXPLOIT = (
    'eventtime=1791271940700000000 tz="+0530" logid="0419016384" type="utm" '
    'subtype="ips" eventtype="signature" level="critical" vd="root" policyid=10 '
    'sessionid=1125640999 srcip=198.51.100.45 srcport=44812 dstip=10.0.14.120 '
    'dstport=443 proto=6 service="HTTPS" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" '
    'vuln_name="CVE-2021-44228" action="detected" severity="critical" direction="incoming" '
    'msg="IPS signature matched in incoming decrypted SSL payload"'
)

SAMPLE_WAF_SQLI_PASSTHROUGH = (
    'eventtime=1791271940800000000 tz="+0530" logid="0951016384" type="utm" '
    'subtype="waf" level="alert" vd="root" policyid=10 sessionid=1125641000 '
    'srcip=198.51.100.45 srcport=44814 dstip=10.0.14.120 dstport=443 proto=6 '
    'service="HTTPS" action="passthrough" msg="SQL Injection: UNION SELECT detected" '
    'httpmethod="GET" url="/api/users?id=1%20UNION%20SELECT%20password%20FROM%20admins"'
)

SAMPLE_SSL_DPI_ANOMALY = (
    'eventtime=1791271940900000000 tz="+0530" logid="0851016384" type="utm" '
    'subtype="ssl" level="warning" vd="root" srcip=203.0.113.88 srcport=50112 '
    'dstip=10.0.14.120 dstport=443 proto=6 action="fail" '
    'msg="SSL deep inspection handshake failed: unsupported cipher or untrusted client hello"'
)

SAMPLE_ESCAPED_QUOTES = (
    'eventtime=1791271941000000000 tz="+0530" logid="0000000013" type="traffic" '
    'subtype="forward" srcip=10.0.1.5 srcport=1000 dstip=10.0.1.6 dstport=80 '
    'user="corp\\\\"admin\\"test" msg="Message with \\"nested\\" quotes and spaces"'
)

SAMPLE_IPV6_LOG = (
    'eventtime=1791271941100000000 tz="+0530" logid="0000000013" type="traffic" '
    'subtype="forward" srcip=2001:db8:85a3::8a2e:370:7334 srcport=44122 '
    'dstip=2001:db8:85a3::1 dstport=443 proto=6 action="deny"'
)
