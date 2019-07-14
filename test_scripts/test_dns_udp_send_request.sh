#!/bin/bash

if [ $# -lt 2 ]; then
    printf "Usage) ${0} [testdata.txt] [DNSSERVER] [TRUE | FALSE]\n"
    exit
fi

if [ ! -f ${1} ]; then
    printf "${1} is not exist.\n"
    exit
fi

DNSSERVER=${2}

if [ $# -lt 3 ]; then
    ENABLE_OUTPUT_LOG=false
else
#   if [ ${3^^} = "TRUE" ]; then    # bash4.0 later
    temp=`tr '[a-z]' '[A-Z]' <<< ${3}`
    if [ $temp = "TRUE" ]; then
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

# 区切り文字を改行コードに指定
IFS=$'\n'
RECORDS=(`cat ${1}`)

printf "DNSSERVER = ${DNSSERVER}\n"

# 区切り文字をスペースに変更
IFS=' '

if "${ENABLE_OUTPUT_LOG}"; then
    printf "LOGFILE=${LOGFILE}\n"

    for RECORD in "${RECORDS[@]}"; do
        # split実行
        set -- ${RECORD}

        printf "python ${TARGET_PROGRAM} ${DNSSERVER} ${1} ${2} >> $LOGFILE\n"
        python ${TARGET_PROGRAM} ${DNSSERVER} ${1} ${2} >> $LOGFILE
    done
else
    for RECORD in "${RECORDS[@]}"; do
        # split実行
        set -- ${RECORD}

        printf "python ${TARGET_PROGRAM} ${DNSSERVER} ${1} ${2}\n"
        python ${TARGET_PROGRAM} ${DNSSERVER} ${1} ${2}
    done
fi
