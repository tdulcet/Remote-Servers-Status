#!/bin/bash

# Teal Dulcet
# Domain expiration monitoring script extracted from the Remote Servers Status Monitoring Script (status.sh)
# This is for testing only

# Requires the whois command

# ./domains.sh

set -e

export LC_ALL=en_US.UTF-8

if [[ $# -ne 0 ]]; then
	echo "Usage: $0" >&2
	exit 1
fi

# List domains in array below or in a "domain-list.txt" file like this: https://github.com/click0/domain-check-2/blob/master/domain-list.txt
DOMAINS=(
	example.com
	example.net
	example.org
	example.edu
)
FILE="domain-list.txt"
[[ -r "$FILE" ]] && DOMAINS+=( $(sort -u "$FILE") )
WARNDAYS=30

RED='\e[0;31m'
YELLOW='\e[0;33m'
GREEN='\e[0;32m'
BOLD='\e[1m'
NC='\e[m' # No Color
NOW=${EPOCHSECONDS:-$(date +%s)}

printf "\n${BOLD}%-35s %-61s %-36s %-9s %s${NC}\n" 'Domain' 'Registrar' 'Expiration Date (current time zone)' 'Days Left' 'DNSSEC'
for d in "${DOMAINS[@]}"; do
	registrar=''
	date=''
	days=''
	server=''
	dnssec=''
	if output=$(whois -h "whois.iana.org" "${d#*.}" 2>&1) && [[ -n "$output" ]]; then
		if aserver=$(echo "$output" | grep -i 'whois:'); then
			server=$(echo "$aserver" | sed -n 's/^[^:]\+[:][[:blank:]]\+//p')
		fi
	fi
	if { output=$(whois "$d" 2>&1) && [[ -n "$output" ]]; } || { [[ -n "$server" ]] && output=$(whois -h "$server" "$d" 2>&1) && [[ -n "$output" ]]; }; then
		if aregistrar=$(echo "$output" | grep -v '^%' | grep -i -A 1 'registrar\.*:\|organization name[[:blank:]]\+\|registrar name:\|record maintained by:\|registrar organization:\|provider:\|support:\|current registar:\|authorized agency\|registered by:\|billing contact:\|contacto financiero'); then
			aregistrar=$(echo "$aregistrar" | head -n 2)
			registrar=$(echo "$aregistrar" | sed -n '/^.\+[]:][.[:blank:]]*/ {$!N; s/^[^]:]\+[]:][.[:space:]]*//p}' | head -n 1)
		elif aregistrar=$(echo "$output" | grep -v '^%' | grep -i -A 1 'registrar'); then
			aregistrar=$(echo "$aregistrar" | head -n 2)
			registrar=$(echo "$aregistrar" | sed -n '/^.\+[[:blank:]]*/ {$!N; s/^[^:]\+[:][[:blank:]]\+//p}' | head -n 1)
		elif aregistrar=$(echo "$output" | grep -i 'copyright (c) [[:print:]]\+ by'); then
			aregistrar=$(echo "$aregistrar" | head -n 1)
			registrar=$(echo "$aregistrar" | sed -n 's/^.\+ by //p')
		else
			registrar="Unknown" # registrar="Error: Could not get domain registrar."
		fi
		
		if adate=$(echo "$output" | grep -i 'expiration\|expires\|expiry\|renewal:\|expire\|paid-till\|valid until\|exp date\|validity\|vencimiento\|registry fee due\|fecha de corte'); then
			adate=$(echo "$adate" | head -n 1 | sed -n 's/^[^]:]\+[]:][.[:blank:]]*//p')
			adate=${adate%.}
			if date=$(date -u -d "$adate" 2>&1) || date=$(date -u -d "${adate//./-}" 2>&1) || date=$(date -u -d "${adate//.//}" 2>&1) || date=$(date -u -d "$(echo "${adate//./-}" | awk -F'[/-]' '{ for(i=NF;i>0;i--) printf "%s%s",$i,(i==1?"\n":"-") }')" 2>&1); then
				date=$(date -d "$date")
				sec=$(( $(date -d "$date" +%s) - NOW ))
				days=$(( sec / 86400 ))
			else
				date="Unknown ($adate)" # date="Error: Could not input domain expiration date ($adate)."
			fi
		else
			date="Unknown" # date="Error: Could not get domain expiration date."
		fi
		
		if adnssec=$(echo "$output" | grep -i -A 1 'dnssec'); then
			adnssec=$(echo "$adnssec" | head -n 2)
			dnssec=$(echo "$adnssec" | sed -n '/^.\+:[[:blank:]]*/ {$!N; s/^[^:]\+:[[:space:]]*//p}' | head -n 1)
		fi
	else
		registrar="Error querying whois server: $(echo "$output" | head -n 1)"
	fi
	printf '\e]8;;http://%s\e\\%s\e]8;;\e\\%*s %-61s ' "$d" "$d" $(( -35 + ${#d} )) '' "$registrar"
	if [[ -n $days ]]; then
		if [[ $days -ge 0 ]]; then
			if [[ $days -lt $WARNDAYS ]]; then
				printf "${YELLOW}%-36s %'-9d${NC}" "$date" "$days"
			else
				printf "${GREEN}%-36s %'-9d${NC}" "$date" "$days"
			fi
		else
			printf "${RED}%-36s %'-9d${NC}" "$date" "$days"
		fi
	else
		printf '%-36s %-9s' "$date"
	fi
	printf ' %s\n' "$dnssec"
	sleep 2
done
echo
