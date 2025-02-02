#!/bin/bash
set -e
IFS=$'\t'

report_err()
{
    echo $'ERR\tInternal error'
}

show_version()
{
    set -e
    trap report_err ERR

    echo $'OK\t'"$(wfb-server --version | head -n1)"
}

do_bind()
{
    set -e
    trap report_err ERR

    tmpdir=$(mktemp -d)
    echo "$1" | base64 -d | tar xz -C "$tmpdir"

    cd "$tmpdir"

    if ! [ -f checksum.txt ] || ! sha1sum --quiet --status --strict -c checksum.txt
    then
        echo $'ERR\tChecksum failed'
        exit 0
    fi

    for i in wifibroadcast.cfg drone.key bind.yaml
    do
        if [ -f $i ]
        then
            cp $i /etc/
        fi
    done

    rm -r "$tmpdir"
    echo "OK"
}

do_unbind()
{
    set -e
    trap report_err ERR

    rm -f /etc/drone.key
    echo "OK"
}

while read -r cmd arg
do
    case $cmd in
        "VERSION")
            show_version
            ;;
        "BIND")
            do_bind "$arg"
            ;;
        "UNBIND")
            do_unbind
            ;;
        *)
            echo $'ERR\tUnsupported command'
            ;;
    esac
done
