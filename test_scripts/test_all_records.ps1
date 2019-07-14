param($dns_server, $resolv_string)

if (-Not($dns_server) -Or -Not($resolv_string)) {
    Write-Host "Usage) "$MyInvocation.MyCommand.Name" [dns server] [resolv string]"
    exit
}

$records = @("", "ANY", "SOA", "NS", "MX", "CNAME", "A", "AAAA", "TXT", "PTR", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3PARAM")
$target_program = "../dns_send_udp_request.py"

foreach($record in $records) {
    Write-Host "python ${target_program} ${dns_server} ${resolv_string} ${record}"
    python ${target_program} ${dns_server} ${resolv_string} ${record}
}
