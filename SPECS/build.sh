#!/bin/bash

set -e

SOURCES="$(rpm --eval '%_topdir')/SOURCES"
mkdir -p "$SOURCES"

function _build() {
    ARCHIVE=$(sed -n 's/^Wrote: //p' <(rpmbuild --clean -bb -v "$1"))
    echo "--> Built rpm archive [${ARCHIVE}] for spec file [${1}]"
    DST="/home/otilmans/flowcorder/repository/rpms/$(basename $ARCHIVE)"
    cp "$ARCHIVE" "$DST"
    sudo yum -y remove flowcorder || true
    sudo yum -y install "$ARCHIVE"
}

function _deps() {
    for dep in python3-daemons.spec\
           python3-ipfix.spec\
           python3-radix.spec; do
    spectool -C "$SOURCES" -g "$dep"
    _build "$dep"
    done
}

function _tool() {
    pushd ../flowcorder
        python3 setup.py sdist --dist-dir "$SOURCES"
    popd
    cp flowcorder_config.cfg "$SOURCES"
    _build flowcorder.spec
}

function do_help() {
    echo "$0 [TARGET [TARGET ...]]: Generate the various rpm files"
    echo ""
    echo "Supported TARGET:"
    echo "-a     Build all packages."
    echo "-f     Build flowcorder."
    echo "-d     Build the dependencies."
    echo "-h     Print this message."
}

while getopts ":ahdf" opt; do
  case $opt in
    d)  _deps;;
    f)  _tool;;
    a)  _deps
          _tool;;
    h)  do_help;;
    \?) echo "Invalid option: -$OPTARG" >&2
          do_help
          exit 0;;
  esac
done

exit 0
