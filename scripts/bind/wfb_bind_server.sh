#!/bin/bash
set -e
IFS=$'\t'

show_version()
{
    echo $'OK\t$(wfb-server --version | head -n1)'
}

report_err()
{
    echo $'ERR\tInternal error'
}

do_bind()
{
    set -e
    trap report_err ERR

    tmpdir=$(mktemp -d)
    echo "$1" | base64 -d | tar xz -C $tmpdir

    cd $tmpdir

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

    rm -r $tmpdir
    echo "OK"
}

while read cmd arg
do
    case $cmd in
        "VERSION")
            show_version
            ;;
        "BIND")
            do_bind "$arg"
            ;;
    esac
done
