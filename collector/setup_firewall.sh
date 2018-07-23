#!/usr/bin/env bash

if [ "x$EUID" != "x0" ]; then
    echo "Run this as root!"
    exit
fi

# $1 cmd $@:2 prefixes
function filter_origin()
{
    # New table to white-list input addresses
    $1 -t filter -N FILTER_ORIGIN
    # Anything from UCL
    for prefix in "${@:2}"; do
        $1 -t filter -A FILTER_ORIGIN -s "$prefix" -j RETURN
    done
    # Accept local addresses
    $1 -t filter -A FILTER_ORIGIN -m addrtype --src-type LOCAL -j RETURN
    # Relatex connection
    $1 -t filter -A FILTER_ORIGIN -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
    # Otherwise drop
    $1 -t filter -A FILTER_ORIGIN -j DROP

    # Set as base filter before anything else
    $1 -t filter -I INPUT -j FILTER_ORIGIN
    $1 -t filter -I FORWARD -j FILTER_ORIGIN
}

filter_origin iptables 130.104.0.0/16 10.0.0.0/8 172.0.0.0/8 192.168.0.0/16
filter_origin ip6tables 2001:6a8:308f::/48 fe80::/10
