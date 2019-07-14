#!/bin/bash

if [ $# -lt 2 ]; then
    printf "Usage) ${0} [dns server] [resolv string]\n"
    exit
fi

records=("" "ANY" "SOA" "NS" "MX" "CNAME" "A" "AAAA" "TXT" "PTR" "DNSKEY" "DS" "RRSIG" "NSEC" "NSEC3PARAM")
TARGET_PROGRAM="../dns_send_udp_request.py"

for record in ${records[@]}; do
    printf "python ${TARGET_PROGRAM} ${1} ${2} ${record}\n"
    python ${TARGET_PROGRAM} ${1} ${2} ${record}
done
