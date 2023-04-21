#!/bin/sh
set -e
case "$1" in
"-e" | "--invoke")
	URI="/ruleset/invoke"
	shift
	;;
"-u" | "--update")
	URI="/ruleset/update"
	shift
	;;
"--gc")
	URI="/ruleset/gc"
	shift
	;;
*)
	echo "usage:  $0 -e '_G.route_default = {\"127.0.6.22:1081\", \"127.0.6.2:1081\"}'"
	echo "        $0 -u @ruleset.lua"
	echo "        $0 --gc"
	exit 1
	;;
esac
if [ -z "$1" ]; then
	set -x
	curl -0vX POST "http://127.0.1.1:9080${URI}"
else
	set -x
	curl -0v "http://127.0.1.1:9080${URI}" \
		--data-binary "$*"
fi
