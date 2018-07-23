#!/bin/bash

declare -A ASNS=( ["Google"]=15169 ["Microsoft"]=8075 ["Facebook"]=32934 )

for ASN in "${!ASNS[@]}"; do
    prefixes="${ASN}.json"
    if [ ! -f "${prefixes}" ]; then
        curl -XGET "https://api.bgpview.io/asn/${ASNS[${ASN}]}/prefixes" > "${prefixes}"
    fi
    python2 -<< _EOF > "${ASN}.prefixes"
import json

data = json.load(open('${prefixes}', 'r'))['data']
print '\n'.join(p['prefix'] for p in data['ipv4_prefixes'])
print '\n'.join(p['prefix'] for p in data['ipv6_prefixes'])
_EOF
done
