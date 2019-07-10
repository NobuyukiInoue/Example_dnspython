#!/bin/bash

if [ $# -lt 2 ]; then
    printf "Usage) ${0} [dns server] [resolv string]\n"
    exit
fi

records=("" "ANY" "SOA" "NS" "MX" "CNAME" "A" "AAAA" "TXT" "PTR" "DNSKEY" "DS" "RRSIG" "NSEC" "NSEC3PARAM")

for record in ${records[@]}; do
    printf "python dns_send_udp_request.py ${1} ${2} ${record}\n"
    python dns_send_udp_request.py ${1} ${2} ${record}
done
