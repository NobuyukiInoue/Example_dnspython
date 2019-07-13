param($dns_server, $resolv_string)

if (-Not($dns_server) -Or -Not($resolv_string)) {
    Write-Host "Usage) "$MyInvocation.MyCommand.Name" [dns server] [resolv string]"
    exit
}

$records = @("", "ANY", "SOA", "NS", "MX", "CNAME", "A", "AAAA", "TXT", "PTR", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3PARAM")

foreach($record in $records) {
    Write-Host "python dns_send_udp_request.py ${dns_server} ${resolv_string} ${record}"
    python dns_send_udp_request.py ${dns_server} ${resolv_string} ${record}
}
