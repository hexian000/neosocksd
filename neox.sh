#!/bin/sh
set -e
ADDR="127.0.1.1:9080"
METHOD="POST"
CONTENT=""
PROXY=""

show_usage() {
    echo "neox.sh"
    echo "  curl wrapper for neosocksd api"
    echo
    echo "usage:"
    echo "  $0 [-x proxy] [-c api] <command sequence>"
    echo
    echo "arguments:"
    echo "  -c <api address>             address to connect, default \"${ADDR}\""
    echo "  -x <proxy>                   socks5 proxy, see example"
    echo "  -u <script>                  update ruleset (/ruleset/update)"
    echo "                               use @filename.lua to load a local file (same below)"
    echo "  -e <script>                  execute statement (/ruleset/invoke)"
    echo "  --gc                         perform full GC (/ruleset/gc)"
    echo
    echo "example:"
    echo "  $0 -e '_G.route_default = rule.proxy(\"192.168.2.1:1080\")'"
    echo "  $0 -e @ruleset_patch.lua"
    echo "  $0 -c 192.168.1.1:9080 -e '_G.route_default = rule.proxy(\"192.168.2.1:1080\")'"
    echo "  $0 -x 192.168.1.1:1080 -c neosocksd.lan -u @ruleset.lua --gc"
    echo
}

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
        make_content -0vX "${METHOD}" -x "socks5h://${PROXY}" "http://neosocksd.lan${URI}"
    else
        make_content -0vX "${METHOD}" "http://${ADDR}${URI}"
    fi
    echo
}

if [ -z "$1" ]; then
    show_usage
    exit 1
fi

while [ -n "$1" ]; do
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
        show_usage
        exit 1
        ;;
    esac
done
