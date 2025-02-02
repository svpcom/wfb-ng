#!/bin/bash
set -e

IFS=$'\t'

echo "VERSION"
read -r status version

if [ "$status" != "OK" ]
then
    echo "Unable to fetch version" 1>&2
    exit 1
fi

echo "Drone firmware: $version" 1>&2

##
## You can add some version compatibility check before sending config files
##

tmpdir=$(mktemp -d)

for i in /etc/wifibroadcast.cfg /etc/drone.key /etc/bind.yaml
do
    if [ -f $i ]
    then
        cp $i "${tmpdir}/"
        (cd "$tmpdir" && sha1sum "$(basename $i)" >> checksum.txt)
    fi
done

echo $'BIND\t'"$(tar czS -C "$tmpdir" . | base64 -w0)"

rm -r "$tmpdir"

read -r status msg

if [ "$status" != "OK" ]
then
    echo "Bind failed: $msg" 1>&2
    exit 1
fi

echo "Bind succeeded" 1>&2
