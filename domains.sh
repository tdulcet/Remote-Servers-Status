#!/bin/bash

# Copyright © Teal Dulcet
# Domain expiration monitoring script extracted from the Remote Servers Status Monitoring Script (status.sh)
# This is for testing only

# Requires the whois command

# ./domains.sh

set -e

if locale -a | grep -iq '^en_US'; then
	export LC_ALL=en_US.UTF-8
else
	export LC_ALL=C.UTF-8
fi

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
[[ -r $FILE ]] && DOMAINS+=($(sort -u "$FILE"))
WARNDAYS=30
COLOR=1

if [[ -n $COLOR ]]; then
	RED='\e[0;31m'
	YELLOW='\e[0;33m'
	GREEN='\e[0;32m'
	BOLD='\e[1m'
	RESET_ALL='\e[m'
fi
NOW=${EPOCHSECONDS:-$(date +%s)}

printf "\n${BOLD}%-35s %-61s %-36s %-9s %s${RESET_ALL}\n" 'Domain' 'Registrar' 'Expiration Date (current time zone)' 'Days Left' 'DNSSEC'
for d in "${DOMAINS[@]}"; do
	registrar=''
	date=''
	days=''
	dnssec=''
	if output=$(curl -sSLf --retry 2 --compressed -H 'Accept: application/rdap+json' "https://rdap.org/domain/$d" 2>&1) && [[ -n $output ]]; then
		if ! registrar=$(echo "$output" | jq -er '.entities[] | select(.roles[]? | contains("registrar")) | if .vcardArray then .vcardArray[1][] | select(.[0] == "fn") | .[3] else .handle end'); then
			registrar="Unknown" # registrar="Error: Could not get domain registrar."
		fi

		if adate=$(echo "$output" | jq -er '.events[] | select(.eventAction | (contains("expiration") or contains("expires"))) | .eventDate'); then
			if date=$(date -ud "$adate" 2>&1); then
				date=$(date -d "$date")
				sec=$(($(date -d "$date" +%s) - NOW))
				days=$((sec / 86400))
			else
				date="Unknown ($adate)" # date="Error: Could not input domain expiration date ($adate)."
			fi
		else
			date="Unknown" # date="Error: Could not get domain expiration date."
		fi

		if adnssec=$(echo "$output" | jq -e 'if .secureDNS.delegationSigned then 1 else 0 end'); then
			if ((adnssec)); then
				dnssec='Yes (signed)'
			else
				dnssec='No (unsigned)'
			fi
		fi
	else
		registrar="Error querying RDAP server: $(echo "$output" | head -n 1)"
	fi
	printf '\e]8;;http://%s\e\\%s\e]8;;\e\\%*s %-61s ' "$d" "$d" $((-35 + ${#d})) '' "$registrar"
	if [[ -n $days ]]; then
		if [[ $days -ge 0 ]]; then
			if [[ $days -lt $WARNDAYS ]]; then
				printf "${YELLOW}%-36s %'-9d${RESET_ALL}" "$date" "$days"
			else
				printf "${GREEN}%-36s %'-9d${RESET_ALL}" "$date" "$days"
			fi
		else
			printf "${RED}%-36s %'-9d${RESET_ALL}" "$date" "$days"
		fi
	else
		printf '%-36s %-9s' "$date" ''
	fi
	printf ' %s\n' "$dnssec"
	sleep 1
done
echo
