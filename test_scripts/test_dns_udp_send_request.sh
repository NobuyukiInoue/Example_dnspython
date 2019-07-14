#!/bin/bash

if [ $# -lt 1 ]; then
    printf "Usage) ${0} [DNSSERVER] [TRUE | FALSE]\n"
    exit
fi

DNSSERVER=${1}

if [ $# -lt 2 ]; then
    ENABLE_OUTPUT_LOG=false
else
    if [ ${2^^} -eq "TRUE" ]; then
        ENABLE_OUTPUT_LOG=true
    else
        ENABLE_OUTPUT_LOG=false
    fi
fi

printf "ENABLE_OUTPUT_LOG = $ENABLE_OUTPUT_LOG\n"

TARGET_PROGRAM="../dns_send_udp_request.py"
TIMESTAMP=`date +%Y%m%d_%H%M%S`
LOGFILE="./log/result_"$TIMESTAMP".log"

if [ -f $LOGFILE ]; then
    printf "$LOGFILE is exist.\n"
    exit
fi

RECORDS=(
". any"
". ns"
"jp any"
"jp ns"
"jp soa"
"jp dnskey"
"jp ds"
"jp nsec3"
"jp nsec3param"
"freebsd.org any"
"_http._tcp.update.freebsd.org srv"
"freebsd.org caa"
)

printf "DNSSERVER=${DNSSERVER}\n"

if "${ENABLE_OUTPUT_LOG}"; then
    printf "LOGFILE=${LOGFILE}\n"

    for RECORD in "${RECORDS[@]}"; do
        printf "python ${TARGET_PROGRAM} ${DNSSERVER} ${RECORD[0]} ${RECORD[1]} >> $LOGFILE\n"
        python ${TARGET_PROGRAM} ${DNSSERVER} ${RECORD[0]} ${RECORD[1]} >> $LOGFILE
    done
else
    for RECORD in "${RECORDS[@]}"; do
        printf "python ${TARGET_PROGRAM} ${DNSSERVER} ${RECORD[0]} ${RECORD[1]}\n"
        python ${TARGET_PROGRAM} ${DNSSERVER} ${RECORD[0]} ${RECORD[1]}
    done
fi
