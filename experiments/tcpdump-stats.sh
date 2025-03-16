#!/bin/bash
#
# License: MIT
# Author: Julien Thomas <jthomas@zenetys.com>
# Copyright: 2020
#

# Expected tcpdump -ttenn output format

# 1528019110.873907 Out c0:3f:d5:69:bb:85 ethertype IPv4 (0x0800), length 344: 192.168.1.20.22 > 192.168.1.17.48984: Flags [P.], seq 389276:389552, ack 253, win 306, options [nop,nop,TS val 467175964 ecr 3174477316], length 276
# 1528019493.101903   M 00:24:d4:c2:98:73 ethertype 802.1Q (0x8100), length 383: vlan 100, p 0, ethertype IPv4, 192.168.27.14.32768 > 239.255.255.250.1900: UDP, length 335
# 1563780719.850833 21:66:da:32:88:e9 > 52:43:11:12:31:2e, ethertype IPv4 (0x0800), length 130: 123.11.13.236.52061 > 123.11.13.30.445: Flags [P.], seq 293443715:293443791, ack 3009377825, win 255, length 76 SMB PACKET: SMBtrans2 (REQUEST)
# 1563893345.298440 52:32:11:12:34:d5 > 78:44:c4:01:12:b2, ethertype IPv4 (0x0800), length 1314: 123.11.13.24 > 123.11.13.232: 2002:c90b:4242::451a:d317.445 > 2002:420b:b3e7::380b:a3e9.64431: Flags [.], seq 599654744:599655964, ack 852480576, win 256, length 1220 SMB-over-TCP packet:(raw data or continuation?)
# 1593434303.175527 d4:be:d9:6b:86:09 > 33:33:00:00:00:0c, ethertype IPv6 (0x86dd), length 718: fe80::8c42:494e:91ab:ba83.50618 > ff02::b.3702: UDP, length 656

export LC_ALL=C
PROGNAME=${0##*/}

# Defaults
PCAP_FILES=()
TCPDUMP_OPTS=()
OVERALL=
DEFAULT_TOP=10
PRINT_UNSUPPORTED=

function exit_usage() {
    local status=${1:-0}
    [[ "$status" != "0" ]] && exec >&2

    echo "\
Usage: $PROGNAME [OPTION...] PCAP-FILE... [-- TCPDUMP-OPTION...]
Print traffic statistics from PCAP file(s).

Available options:
  -a, --all                 Overall stats instead of per PCAP file stats.
  -t, --top=NUMBER          Top n connections, default $DEFAULT_TOP.
  -u, --unsupported         Print unsupported tcpdump output to stderr.
  -h, --help                Display this help.
"
    exit "$status"
}

function check_cmd() {
    local check="_CHECK_CMD_${1//[^[:alnum:]_]/_}"
    if [[ -z ${!check} ]]; then
        type -P "$1" >/dev/null 2>&1
        eval "$check=\$?"
    fi
    if [[ $QUIET != 1 && ${!check} != 0 ]]; then
        echo "ERROR: $PROGNAME: Command not found: $1" >&2
    fi
    return "${!check}"
}

if QUIET=1 check_cmd pv; then
    function pv() { command pv -w 80 "$@"; }
else
    function pv() { cat "$@"; }
fi

function cat_file() {
    local prog
    case "${1##*.}" in
        gz*) prog=zcat ;;
        bz2*) prog=bzcat ;;
        xz*) prog=xzcat ;;
        lz*|lzma*) prog=lzcat ;;
        *) prog=cat ;;
    esac
    if [[ -n $CHECK_CMD ]]; then
        check_cmd "$prog"
    else
        pv "$1" | "$prog"
    fi
}

function compute() {
    # Use sed to extract capture groups to maximize compatibility.
    # For instance, Busybox awk supports match() but does not support the
    # capture group array as 3rd argument like in gawk.
    sed -n -r -e 's!^([0-9.]+) .*\(0x[0-9A-Fa-f]+\), length ([0-9]+): ([^,]+, )*([^ ]+) > ([0-9A-Fa-f:.]+): ([0-9A-Fa-f:]+\.([0-9]+) > [0-9A-Fa-f:]+\.([0-9]+))?.*!\1\t\2\t\4\t\5\t\7\t\8!p' -e 't' -e 's,^.*,# \0,p' |
        awk -v "PROGNAME=$PROGNAME" \
            -v "PRINT_UNSUPPORTED=$PRINT_UNSUPPORTED" \
    '
    {
        if ($1 == "#") {
            if (PRINT_UNSUPPORTED)
                print "ERROR: " PROGNAME ": Unsupported tcpdump output: " $0 >> "/dev/stderr";
        }
        else {
            if ($5 != "" && $6 != "")
                key = $3 "." $5 " > " $4 "." $6;
            else
                key = $3 " > " $4;

            if (key_start[key] == "")
                key_start[key] = $1;
            key_end[key] = $1;
            key_bytes[key] += $2;

            if (key_start["*"] == "")
                key_start["*"] = $1;
            key_end["*"] = $1;
            key_bytes["*"] += $2;
        }
    }
    END {
        for (key in key_bytes) {
            duration = key_end[key] - key_start[key];
            if (duration > 0) {
                rate = (key_bytes[key] * 8) / duration;
                printf("%s\t%.2f\t%.2f\t%.2f\n", key, key_bytes[key], rate, duration);
            }
        }
    }
    '
}

function pretty() {
    awk -F $'\t' \
    '
    function human(input, mult, _symbol) {
        _symbol = 1;
        while (input >= mult && _symbol < HUMAN_SYMBOLS_LEN) {
            _symbol++;
            input = input / mult;
        }
        return sprintf("%.2f %s", input, HUMAN_SYMBOLS[_symbol]);
    }
    function round(n) {
        return sprintf("%0.f", n) + 0;
    }
    function dhms(s) {
        out = "";
        s = round(s);
        d = int(s/86400);
        if (d > 0) out = out d "d";
        s = s - d*86400;
        h = int(s/3600);
        if (h > 0 || out != "") out = out h "h";
        s = s - h*3600;
        m = int(s/60);
        if (m > 0 || out != "") out = out m "m";
        s = s - m*60;
        out = out s "s";
        return out;
    }
    BEGIN {
        HUMAN_SYMBOLS_LEN = split(" ,K,M,G,T", HUMAN_SYMBOLS, ",");
    }
    {
        key = $1;
        bytes = human($2, 1024) "B";
        bitrate = human($3, 1000) "bps";
        duration = dhms($4);
        printf("%-48s %10s %12s %12s\n", key, bytes, duration, bitrate);
    }
    '
}

for cmd in awk cat sort tcpdump; do
    check_cmd "$cmd" || exit 2
done

while (( $# > 0 )); do
    case "$1" in
        -a|--all)
            OVERALL=1
            ;;
        -t|--top)
            shift
            [[ -z $1 || -n ${1//[0-9]} ]] && exit_usage 1
            TOP=$1
            ;;
        -u|--unsupported)
            PRINT_UNSUPPORTED=1
            ;;
        -h|--help)
            exit_usage
            ;;
        --)
            shift
            break
            ;;
        *)
            if [[ ! -f $1 || ! -r $1 ]]; then
                echo "ERROR: $PROGNAME: Cannot read file: $1" >&2
                exit 2
            fi
            CHECK_CMD=1 cat_file "$1" || exit 2
            PCAP_FILES+=( "$1" )
            ;;
    esac
    shift
done

[[ -z $PCAP_FILES ]] && exit_usage 1
[[ -z $TOP ]] && TOP=$DEFAULT_TOP

if [[ $TOP != 0 ]]; then
    check_cmd head || exit 2
fi

TCPDUMP_OPTS+=( "$@" )

if [[ $OVERALL ]]; then
    for pcap in "${PCAP_FILES[@]}"; do
        echo "# PCAP file $pcap" >&2
        cat_file "$pcap" |
            tcpdump -ttennr - "${TCPDUMP_OPTS[@]}"
    done |
        compute |
        sort -t $'\t' -k 2nr,2 |
        { [[ $TOP == 0 ]] && cat || head -n "$TOP"; } |
        pretty
else
    for pcap in "${PCAP_FILES[@]}"; do
        echo "# PCAP file $pcap" >&2
        cat_file "$pcap" |
            tcpdump -ttennr - "${TCPDUMP_OPTS[@]}" |
            compute |
            sort -t $'\t' -k 2nr,2 |
            { [[ $TOP == 0 ]] && cat || head -n "$TOP"; } |
            pretty
    done
fi
