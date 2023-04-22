#!/bin/sh
set -e
ADDR="127.0.1.1:9080"
METHOD="POST"
CONTENT=""
PROXY=""

make_content() {
    if [ -z "${CONTENT}" ]; then
        curl "$@"
    else
        curl "$@" --data-binary "${CONTENT}"
    fi
}

make_call() {
    echo " >>> ${METHOD} ${URI} ${CONTENT}"
    if [ -n "${PROXY}" ]; then
        make_content -0vX "${METHOD}" -x "socks4a://${PROXY}" "http://neosocksd.lan${URI}"
    else
        make_content -0vX "${METHOD}" "http://${ADDR}${URI}"
    fi
    echo
}

while [ $# -gt 0 ]; do
    case "$1" in
    "-c" | "--connect")
        ADDR="$2"
        shift 2
        ;;
    "-x" | "--proxy")
        PROXY="$2"
        shift 2
        ;;
    "-e" | "--invoke")
        URI="/ruleset/invoke"
        CONTENT="$2"
        make_call
        shift 2
        ;;
    "-u" | "--update")
        URI="/ruleset/update"
        CONTENT="$2"
        make_call
        shift 2
        ;;
    "--gc")
        URI="/ruleset/gc"
        CONTENT=""
        make_call
        shift
        ;;
    *)
        echo "usage:  $0 -e '_G.route_default = {\"127.0.6.22:1081\", \"127.0.6.2:1081\"}'"
        echo "        $0 -u @ruleset.lua"
        echo "        $0 -x 192.168.1.1:1080 -u @ruleset.lua --gc"
        exit 1
        ;;
    esac
done
