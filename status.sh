#!/bin/bash

# Teal Dulcet
# Monitors the status of one or more remote servers and send notifications when status changes state

# Requires the curl, netcat, ping, dig, delv, whois and openssl commands
# sudo apt-get update
# sudo apt-get install dnsutils
# sudo apt-get install bind9
# sudo apt-get install whois

# Optional Visual monitoring requires Firefox (57 or greater) and ImageMagick
# sudo apt-get install firefox or sudo apt-get install firefox-esr
# sudo apt-get install imagemagick

# Run once
# ./status.sh

# Run every minute
# crontab -l | { cat; echo "* * * * * cd \"$PWD\" && ./status.sh > /dev/null"; } | crontab -

# Run every 5 minutes
# crontab -l | { cat; echo "*/5 * * * * cd \"$PWD\" && ./status.sh > /dev/null"; } | crontab -

set -e

export LC_ALL=en_US.UTF-8

if [[ "$#" -ne 0 ]]; then
	echo "Usage: $0" >&2
	exit 1
fi

# Set the variables below

# Send e-mails
# Comment this out to temporally disable
# SEND=1

# To e-mail addresses
# Send SMSs by using your mobile providers e-mail to SMS or MMS gateway (https://en.wikipedia.org/wiki/SMS_gateway)
TOEMAILS=(

)

# Optional From e-mail address
# FROMEMAIL="Example <example@example.com>"

# Optional SMTP server to send e-mails
# Supported protocols: "smtp" and "smtps".
# Requires From e-mail address above

# SMTP="smtps://mail.example.com"
# USERNAME="example"
# PASSWORD="password"

# Optional S/MIME Certificate to digitally sign the e-mails
# Requires SMTP server above

# Get a free S/MIME Certificate: https://www.instantssl.com/products/free-secure-email-certificate (Must use the Firefox browser)
# List of more free S/MIME Certificates: http://kb.mozillazine.org/Getting_an_SMIME_certificate
# After installing the certificate in Firefox, open the Firefox menu "≡", click on "⚙️ Options" > "🔒 Privacy & Security", under "Security" and "Certificates" click on "View Certificates…", click on the certificate > "Backup…", browse to the location of this script, give it a name and click on "Save". Enter the name for the CERT variable below. Can also import the certificate into a mail client, such as Thunderbird.

# CERT="cert.p12"

CLIENTCERT="cert.pem"

# Website (HTTP(S)) Monitors

WEBSITENAMES=(
# "Example Website"
)

# URL syntax: <scheme>://[user]:[password]@<host>:[port]/[path]
# Example: https://user:password@www.example.com:443/path/
# Supported protocols: "http" and "https".

URLS=(
# https://www.example.com/
)

# Port Monitors

PORTNAMES=(
# "Example IMAP Mail Server"
# "Example SMTP Mail Server"
)

PORTHOSTNAMES=(
# mail.example.com
# mail.example.com
)

PORTS=(
# 993
# 465
)

# StartTLS Protocols
# If the port does not support StartTLS, put an empty string: ''.
# Supported protocols (Source: https://www.openssl.org/docs/manmaster/man1/s_client.html): "smtp", "pop3", "imap", "ftp", "xmpp", "xmpp-server", "irc", "postgres", "mysql", "lmtp", "nntp", "sieve" and "ldap".
PROTOCOLS=(
# ''
# ''
)

# Ping Monitors

PINGNAMES=(
# "Example"
)

PINGHOSTNAMES=(
# example.com
)

# Days to warn before DNSSEC, certificate and domain expiration
WARNDAYS=3

# Log file
LOG="status.log"

# Public DNS servers that validate responses DNS Security Extensions (DNSSEC) to use with the dig and delv commands
# Use if your ISP does not support DNSSEC and you are not running a local DNSSEC validating recursive resolver, such as bind9 (https://www.perfacilis.com/blog/systeembeheer/linux/setup-a-public-dns-server.html)

# IPv4 DNS server
DNS="1.1.1.1" # Cloudflare
# DNS="8.8.8.8" # Google Public DNS

# IPv6 DNS server
# DNS="2606:4700:4700::1111" # Cloudflare
# DNS="2001:4860:4860::8888" # Google Public DNS

# DNS blacklists

# Domain Blacklists
# Add more from here, if needed: https://hetrixtools.com/blacklist-check/ (enter any domain and copy the blacklists)
DOMAINBLACKLISTS=(
dbl.spamhaus.org # Spamhaus Domain Block List
)

# IPv4 Blacklists
# Add more from here, if needed (note that there is a lot of duplication between these sources): https://hetrixtools.com/blacklist-check/ (enter any IPv4 address and copy the blacklists)
# https://github.com/adionditsak/blacklist-check-unix-linux-utility/blob/master/bl (copy from bottom of file)
# https://github.com/gsauthof/utility/blob/master/check-dnsbl.py (copy from top of file)
# https://gist.github.com/tbreuss/74da96ff5f976ce770e6628badbd7dfc (copy from near top of file)
# https://github.com/lukecyca/check-rbl/blob/master/check-rbl.pl (copy from top of file)
# See comparison here: https://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists
IPv4BLACKLISTS=(
zen.spamhaus.org # Spamhaus Block List
)

# IPv6 Blacklists
# Some of the IPv4 Blacklists from the sources above also support IPv6
IPv6BLACKLISTS=(
zen.spamhaus.org # Spamhaus Block List
)

# Visual difference maximum percentage
# Uncomment this to enable visual monitoring
# PERCENTAGE=20 # 20%

# Do not change anything below this

RED='\e[0;31m'
YELLOW='\e[0;33m'
GREEN='\e[0;32m'
BOLD='\e[1m'
NC='\e[0m' # No Color
# COLUMNS=$(tput cols)

NOW=$(date -u)
SECONDS=0

# Lock directory
# LOCKDIR="~lock"
# Lock file
LOCK="~lock"

# Check if on Linux
if ! echo "$OSTYPE" | grep -iq "linux"; then
	echo "Error: This script must be run on Linux." >&2
	exit 1
fi

exec 200>"$LOCK"

# if ! mkdir "$LOCKDIR"; then
if ! flock -n 200; then
	echo "Error: This script is already running." >&2
	exit 1
fi

# trap 'rm -r "$LOCKDIR"' EXIT

echo -n "Checking internet connection... "

# Check connectivity
if ! ping4 -q -c 1 google.com > /dev/null 2>&1; then
	echo -e "\nWarning: Could not reach google.com over IPv4.\n"
	IPv4=1
fi

if ! ping6 -q -c 1 google.com > /dev/null 2>&1; then
	echo -e "\nWarning: Could not reach google.com over IPv6.\n"
	IPv6=1
fi

if [[ -n "$IPv4" && -n "$IPv6" ]]; then
	echo -e "\nError: Could not reach well known host google.com, please check your internet connection.\n" >&2
	exit 1
fi

echo -e "done\n"

# IPv4 address regular expression
# RE='^2([0-4][0-9]|5[0-5])|1?[0-9][0-9]{1,2}(\.(2([0-4][0-9]|5[0-5])|1?[0-9]{1,2})){3}$'
IPv4='((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])'
IPv4RE='^'"$IPv4"'$'

# IPv6 address regular expression
# RE='^[[:xdigit:]]{1,4}(:[[:xdigit:]]{1,4}){7}$'
IPv6='(([[:xdigit:]]{1,4}:){7}[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,7}:|([[:xdigit:]]{1,4}:){1,6}:[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,5}(:[[:xdigit:]]{1,4}){1,2}|([[:xdigit:]]{1,4}:){1,4}(:[[:xdigit:]]{1,4}){1,3}|([[:xdigit:]]{1,4}:){1,3}(:[[:xdigit:]]{1,4}){1,4}|([[:xdigit:]]{1,4}:){1,2}(:[[:xdigit:]]{1,4}){1,5}|[[:xdigit:]]{1,4}:((:[[:xdigit:]]{1,4}){1,6})|:((:[[:xdigit:]]{1,4}){1,7}|:))'
IPv6RE='^'"$IPv6"'$'

# URL regular expression
URLRE='^((https?:)//)?(([^:]{1,128}):([^@]{1,256})@)?(((xn--)?[[:alnum:]][[:alnum:]\-]{0,61}[[:alnum:]]\.)+(xn--)?[a-zA-Z]{2,63}|'"$IPv4"'|'"$IPv6"')(:([[:digit:]]{1,5}))?(.*)?$'
# for i in "${!BASH_REMATCH[@]}"; do echo -e "$i\t${BASH_REMATCH[$i]}"; done

if [[ "${#TOEMAILS[@]}" -eq 0 ]]; then
	echo "Error: One or more To e-mail addresses are required." >&2
	exit 1
fi

# Adapted from: https://github.com/mail-in-a-box/mailinabox/blob/master/setup/network-checks.sh
if ! [[ -n "$FROMEMAIL" && -n "$SMTP" && -n "$USERNAME" && -n "$PASSWORD" ]] && ! nc -z -w5 aspmx.l.google.com 25; then
	echo -e "Warning: Could not reach Google's mail server on port 25. Port 25 seems to be blocked by your network. You will need to set the SMTP server variables in order to send e-mails.\n"
fi

EMAILS=( "${TOEMAILS[@]}" )
EMAIL=$FROMEMAIL

# Get e-mail address(es): "Example <example@example.com>" -> "example@example.com"
RE='^([[:graph:]]{1,64}@[-.[:alnum:]]{4,254})|(([[:print:]]*) *<([[:graph:]]{1,64}@[-.[:alnum:]]{4,254})>)$'
for i in "${!EMAILS[@]}"; do
	if [[ ${EMAILS[$i]} =~ $RE ]]; then
		EMAILS[$i]=${BASH_REMATCH[1]:-${BASH_REMATCH[4]}}
	fi
done

if [[ -n "$EMAIL" ]] && [[ $EMAIL =~ $RE ]]; then
	EMAIL=${BASH_REMATCH[1]:-${BASH_REMATCH[4]}}
fi

RE1='^.{6,254}$'
RE2='^.{1,64}@'
RE3='^[[:alnum:]!#\$%&'\''\*\+/=?^_\`{|}~-]+(\.[[:alnum:]!#\$%&'\''\*\+/=?^_\`{|}~-]+)*@((xn--)?[[:alnum:]][[:alnum:]\-]{0,61}[[:alnum:]]\.)+(xn--)?[a-zA-Z]{2,63}$'
for email in "${EMAILS[@]}"; do
	if ! [[ $email =~ $RE1 && $email =~ $RE2 && $email =~ $RE3 ]]; then
		echo "Error: \"$email\" is not a valid e-mail address." >&2
		exit 1
	fi
done

if [[ -n "$EMAIL" ]] && ! [[ $EMAIL =~ $RE1 && $EMAIL =~ $RE2 && $EMAIL =~ $RE3 ]]; then
	echo "Error: \"$EMAIL\" is not a valid e-mail address." >&2
	exit 1
fi

if [[ "${#WEBSITENAMES[@]}" -ne "${#URLS[@]}" ]]; then
	echo "Error: For the Website (HTTP(S)) Monitors, the number of Names and URLs must be equal." >&2
	exit 1
fi

if [[ "${#PORTNAMES[@]}" -ne "${#PORTHOSTNAMES[@]}" || "${#PORTHOSTNAMES[@]}" -ne "${#PORTS[@]}" || "${#PORTS[@]}" -ne "${#PROTOCOLS[@]}" ]]; then
	echo "Error: For the Port Monitors, the number of Names, Hostnames, Ports and Protocols must be equal." >&2
	exit 1
fi

if [[ "${#PINGNAMES[@]}" -ne "${#PINGHOSTNAMES[@]}" ]]; then
	echo "Error: For the Ping Monitors, the number of Names and Hostnames must be equal." >&2
	exit 1
fi

if [[ -n "$CERT" ]]; then
	if [[ ! -r "$CERT" && ! -f "$CLIENTCERT" ]]; then
		echo "Error: \"$CERT\" certificate file does not exist." >&2
		exit 1
	fi

	if [[ ! -f "$CLIENTCERT" ]]; then
		echo -e "Saving the client certificate from \"$CERT\" to \"$CLIENTCERT\""
		echo -e "Please enter the password when prompted.\n"
		openssl pkcs12 -in "$CERT" -out "$CLIENTCERT" -clcerts -nodes
	fi
	
	# if ! output=$(openssl verify -verify_email "$EMAIL" "$CLIENTCERT" 2>/dev/null); then
		# echo "Error verifying the S/MIME Certificate: $output" >&2
		# exit 1
	# fi

	if aissuer=$(openssl x509 -in "$CLIENTCERT" -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq); then
		issuer=$(echo "$aissuer" | awk -F'=' '/commonName=/ { print $2 }')
	else
		issuer=''
	fi
	date=$(openssl x509 -in "$CLIENTCERT" -noout -enddate | awk -F'=' '/notAfter=/ { print $2 }')
	if openssl x509 -in "$CLIENTCERT" -noout -checkend 0 > /dev/null; then
		sec=$(( $(date -d "$date" +%s) - $(date -d "$NOW" +%s) ))
		if [[ $(( sec / 86400 )) -lt $WARNDAYS ]]; then
			echo -e "Warning: The S/MIME Certificate $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expires in less than $WARNDAYS days ($(date -d "$date")).\n"
		fi
	else
		echo "Error: The S/MIME Certificate $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expired $(date -d "$date")." >&2
		exit 1
	fi
fi

# Output
# out <text>
# out() {
	# echo -e "$1" | fold -s -w "$COLUMNS"
# }

# Log to file
# log <text>
log() {
	echo -e -n "[$(date)]  $1" >> "$LOG"
}

# Send e-mail, with optional message and attachment
# Supports Unicode characters in subject and message
# send <subject> [message] [attachment]
send() {
	local headers message
	if [[ -n "$SEND" ]]; then
		if [[ -n "$EMAIL" && -n "$SMTP" && -n "$USERNAME" && -n "$PASSWORD" ]]; then
			headers="From: $FROMEMAIL\nTo: ${TOEMAILS[0]}$([[ "${#TOEMAILS[@]}" -gt 1 ]] && printf ', %s' "${TOEMAILS[@]:1}")\nSubject: =?utf-8?B?$(echo "$1" | base64 -w 0)?=\nDate: $(date -R)\n"
			if [[ -n "$3" ]]; then
				message="MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"MULTIPART-MIXED-BOUNDARY\"\n\n--MULTIPART-MIXED-BOUNDARY\nContent-Type: text/plain; charset=utf-8\n\n$2\n--MULTIPART-MIXED-BOUNDARY\nContent-Type: $(file --mime-type "$3" | sed -n 's/^.\+: //p')\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename=\"$3\"\n\n$(base64 "$3")\n--MULTIPART-MIXED-BOUNDARY--"
			else
				message="Content-Type: text/plain; charset=utf-8\n\n$2"
			fi
			if [[ -n "$CERT" ]]; then
				echo -e "$headers$(echo -e "$message" | openssl cms -sign -signer "$CLIENTCERT")" | eval curl -sS "$SMTP" --mail-from "$EMAIL" $(printf -- '--mail-rcpt "%s" ' "${EMAILS[@]}") -T - -u "$USERNAME:$PASSWORD"
			else
				echo -e "$headers$message" | eval curl -sS "$SMTP" --mail-from "$EMAIL" $(printf -- '--mail-rcpt "%s" ' "${EMAILS[@]}") -T - -u "$USERNAME:$PASSWORD"
			fi
		else
			{ echo -e "$2"; [[ -n "$3" ]] && uuencode "$3" "$3"; } | eval mail $([[ -n "$EMAIL" ]] && echo "-r \"$EMAIL\"" || echo) -s "$1" -- "${EMAILS[@]}"
		fi
	fi
}

# getSecondsAsDigitalClock <seconds>
getSecondsAsDigitalClock() {
	local sec_num=$1
	local d=$(( sec_num / 86400 ))
	local h=$(( (sec_num % 86400) / 3600 ))
	local m=$(( (sec_num % 86400 % 3600) / 60 ))
	local s=$(( sec_num % 86400 % 3600 % 60 ))
	local text=''
	if [[ $d -gt 0 ]]; then
		text+="$d days "
	fi
	if [[ $d -gt 0 || $h -gt 0 ]]; then
		text+="$([[ $h -lt 10 ]] && echo "0$h" || echo $h) hours "
	fi
	if [[ $d -gt 0 || $h -gt 0 || $m -gt 0 ]]; then
		text+="$([[ $m -lt 10 ]] && echo "0$m" || echo $m) minutes "
	fi
	if [[ $d -gt 0 || $h -gt 0 || $m -gt 0 || $s -gt 0 ]]; then
		text+="$([[ $s -lt 10 ]] && echo "0$s" || echo $s) seconds"
	fi
	echo "$text"
}

# stopwatch <date and time>
stopwatch() {
	getSecondsAsDigitalClock "$(( $(date -d "$NOW" +%s) - $(date -d "$1" +%s) ))"
}

# timer <date and time>
timer() {
	getSecondsAsDigitalClock "$(( $(date -d "$1" +%s) - $(date -d "$NOW" +%s) ))"
}

# up
up() {
	local temp
	temp="It was down for $(stopwatch "$(<"$FILE")")."
	rm "$FILE"
	echo -e "\t\t$temp"
	MESSAGE+="$temp\n"
	log "$MESSAGE"
	send "⬆️ $SUBJECT is UP"'!' "$MESSAGE"
}

# down
down() {
	date -u > "$FILE"
	log "$MESSAGE"
	send "⬇️ $SUBJECT is DOWN"'!' "$MESSAGE\nThis script will alert you when it is back up.\n"
}

# error <error file> <subject> <message> [attachment]
error() {
	if [[ ! -r "$1" ]]; then
		touch "$1"
		log "$3"
		send "$2" "$3" "$4"
	fi
}

# noerror <error file>
noerror() {
	if [[ -r "$1" ]]; then
		rm "$1"
	fi
}

# Check DNS Security Extensions (DNSSEC) signature expiration
# Adapted from: https://github.com/menandmice-services/dns-monitoring-scripts/blob/master/test12.sh
# dnssec <hostname>
dnssec() {
	local type date sec
	if [[ ! "$1" =~ $IPv4RE && ! "$1" =~ $IPv6RE ]]; then
		for type in soa; do
			if if [[ -n "$DNS" ]]; then output=$(dig +noall +answer +authority +cd +dnssec "$type" "${1}" "@$DNS"); else output=$(dig +noall +answer +authority +cd +dnssec "$type" "${1}"); fi && [[ -n "$output" ]]; then
				if date=$(echo "$output" | awk "\$4 == \"RRSIG\" && \$5 == \"${type^^}\" {print \$9}") && [[ -n "$date" ]]; then
					date="${date:0:8} ${date:8:2}:${date:10:2}:${date:12:2}"
					date=$(date -u -d "$date" +%s)
					sec=$(( date - $(date -d "$NOW" +%s) ))
					if [[ $sec -gt 0 ]]; then
						if [[ $(( sec / 86400 )) -lt $WARNDAYS ]]; then
							echo -e "\t\t⚠🔒 DNSSEC signature for the ${type^^} resource record expires in ${YELLOW}$(getSecondsAsDigitalClock "$sec")${NC}."
							
							# error ".dnssec.$type.expires$FILE" "⚠️🔒 DNSSEC signature for $SUBJECT expires in < $WARNDAYS days" "The DNSSEC signature for the ${type^^} Resource Record (RR) for $MESSAGE expires in less than $WARNDAYS days ($(date -d "@$date")).\n"
						else
							echo -e "\t\t🔒 DNSSEC signature for the ${type^^} resource record expires in $(getSecondsAsDigitalClock "$sec")."
							
							# noerror ".dnssec.$type.expires$FILE"
							# noerror ".dnssec.$type.expired$FILE"
						fi
					else
						echo -e "\t\t✖️🔓 DNSSEC signature for the ${type^^} resource record expired ${RED}$(date -d "@$date")${NC}."
						
						# error ".dnssec.$type.expired$FILE" "❌🔓 DNSSEC signature for $SUBJECT expired" "The DNSSEC signature for the ${type^^} Resource Record (RR) for $MESSAGE expired $(date -d "@$date").\n"
					fi
				fi
			fi
		done
	fi
}

# Check certificate revocation
# Adapted from: https://github.com/drwetter/testssl.sh/blob/3.0/testssl.sh
# revocation <certificate>
revocation() {
	local certs cert chain file uri temp adate response length reason
	# Certificates
	certs=$(echo "$1" | sed -n '/^Certificate chain/,$p' | sed -n '/^-----BEGIN CERTIFICATE-----/,/^-----END CERTIFICATE-----/p')
	# Server certificate
	cert=$(echo "$certs" | awk '/^-----BEGIN CERTIFICATE-----/{p=1} p; /^-----END CERTIFICATE-----/{exit}')
	# Certificate chain
	chain=${certs//$cert/}
	output=$(echo "$1" | openssl x509 -noout -text)
	# Check Certificate Revocation List (CRL)
	if uri=$(echo "$output" | grep -i -A 4 'X509v3 CRL Distribution Points'); then
		# Do not check CRL again until the next update for performance
		file=".cert.crl$FILE"
		if [[ ! -r "$file" ]] || [[ -r "$file" && $(( $(date -d "$NOW" +%s) - $(date -d "$(<"$file")" +%s) )) -gt 0 ]]; then
			uri=$(echo "$uri" | grep -i 'uri' | sed -n 's/^[^:]\+://p')
			temp=$(mktemp)
			# Download CRL
			if output=$(curl -sSo "$temp" "$uri"); then
				if openssl crl -inform DER -in "$temp" -outform PEM -out "$temp"; then
					adate=$(openssl crl -inform PEM -in "$temp" -noout -text | grep -i 'next update' | sed -n 's/^[^:]\+: //p')
					if if [[ -n "$chain" ]]; then output=$(openssl verify -crl_check -CAfile "$temp" -untrusted <(echo "$chain") <(echo "$cert") 2>&1); else output=$(openssl verify -crl_check -CAfile "$temp" <(echo "$cert") 2>&1); fi; then
						# echo -e "\t\t🔒 Certificate Revocation List (CRL): Certificate has NOT been revoked (${output#*: })."
						noerror ".cert.crl.error$FILE"
					else
						if response=$(echo "$output" | grep -i 'error') && echo "$response" | grep -iq "revoked"; then
							reason=$(echo "$response" | head -n 1 | sed -n 's/^[^:]\+: //p')
							echo -e "\t\t✖️🔓 Certificate Revocation List (CRL): Certificate has been revoked ($reason)."
							
							error ".cert.crl.error$FILE" "❌🔏 CRL: Certificate for $SUBJECT revoked" "Certificate Revocation List (CRL): The certificate for $MESSAGE has been revoked ($reason).\n"
						else
							reason=$(echo "$response" | head -n 1 | sed -n 's/^[^:]\+: //p')
							echo -e "\t\t✖️🔓 Error checking Certificate Revocation List (CRL): $reason"
							
							error ".cert.crl.error$FILE" "❌🔏 Error checking CRL for $SUBJECT" "Error checking Certificate Revocation List (CRL) for $MESSAGE: $reason.\n"
						fi
					fi
					date -u -d "$adate" > "$file"
				else
					echo "Error: Could not convert the Certificate Revocation List (CRL) file to PEM format."
				fi
			else
				echo "Error: Could not download the Certificate Revocation List (CRL) file ($uri): $(echo "$output" | head -n 1 | sed -n 's/^[^:]\+: ([^)]\+) //p')"
			fi
			rm -f "$temp"
		else
			echo -e "\t\tℹ Certificate Revocation List (CRL) has already been checked since the last update. Next update: $(date -d "$(<"$file")")"
		fi
	fi
	if [[ -n "$chain" ]]; then
		# Check Online Certificate Status Protocol (OCSP) stapling
		if ! echo "$1" | grep -iq 'ocsp response: no response sent'; then
			# TLS 1.2 or earlier
			if echo "$1" | grep -q 'CertificateStatus'; then
				response=$(echo "$1" | sed -n '/CertificateStatus/,/<<</{//!p;}')
				response=${response//[[:space:]]/}
				response=${response:8}
			# TLS 1.3
			elif length=$(echo "$1" | grep 'TLS server extension "status request" (id=5), len='); then
				length=$(( 2 * ${length##*=} ))
				response=$(echo "$1" | sed -n '/^TLS server extension "status request" (id=5), len=/,/<<</{//!p;}' | awk '{ print $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 $17 }')
				response=${response//[-[:space:]]/}
				response="${response:0:length}"
			else
				echo "Error: Could not get stapled OCSP response."
			fi
			if openssl verify <(echo "$chain") >/dev/null 2>&1; then
				# Verifying stapled OCSP response
				if output=$(openssl ocsp -issuer <(echo "$chain") -cert <(echo "$cert") -no_nonce -respin <(echo "${response:8}" | xxd -r -p) 2>&1) && echo "$output" | grep -iq "response verify ok"; then
					response=$(echo "$output" | grep '^/dev/fd/.\+: ')
					reason=${response#*: }
					if echo "$response" | grep -iq "good"; then
						# echo -e "\t\t🔒 OCSP stapling: Certificate has NOT been revoked ($reason)."
						noerror ".cert.ocsp.error$FILE"
					elif echo "$response" | grep -iq "revoked"; then
						echo -e "\t\t✖️🔓 OCSP stapling: Certificate has been revoked ($reason)."
						
						error ".cert.ocsp.error$FILE" "❌🔏 OCSP stapling: Certificate for $SUBJECT revoked" "Online Certificate Status Protocol (OCSP) stapling: The certificate for $MESSAGE has been revoked ($reason).\n"
					else
						echo -e "\t\t✖️🔓 Error checking stapled OCSP response: $reason"
						
						error ".cert.ocsp.error$FILE" "❌🔏 Error checking stapled OCSP response for $SUBJECT" "Error checking stapled Online Certificate Status Protocol (OCSP) response for $MESSAGE: $reason.\n"
					fi
				else
					echo -e "\t\t✖️🔓 Error reading stapled OCSP response: $output"
				fi
			else
				echo "Error: Could not verify certificate chain."
			fi
		# Check Online Certificate Status Protocol (OCSP)
		elif uri=$(echo "$1" | openssl x509 -noout -ocsp_uri) && [[ -n "$uri" ]]; then
			# Do not check OCSP again until the next update for performance
			file=".cert.ocsp$FILE"
			if [[ ! -r "$file" ]] || [[ -r "$file" && $(( $(date -d "$NOW" +%s) - $(date -d "$(<"$file")" +%s) )) -gt 0 ]]; then
				if openssl verify <(echo "$chain") >/dev/null 2>&1; then
					# Query OCSP responder
					if output=$(openssl ocsp -issuer <(echo "$chain") -cert <(echo "$cert") -url "$uri" 2>&1) && echo "$output" | grep -iq "response verify ok"; then
						adate=$(echo "$output" | grep -i 'next update' | head -n 1 | sed -n 's/^[^:]\+: //p')
						response=$(echo "$output" | grep '^/dev/fd/.\+: ')
						reason=${response#*: }
						if echo "$response" | grep -iq "good"; then
							# echo -e "\t\t🔒 OCSP: Certificate has NOT been revoked ($reason)."
							noerror ".cert.ocsp.error$FILE"
						elif echo "$response" | grep -iq "revoked"; then
							echo -e "\t\t✖️🔓 OCSP: Certificate has been revoked ($reason)."
							
							error ".cert.ocsp.error$FILE" "❌🔏 OCSP: Certificate for $SUBJECT revoked" "Online Certificate Status Protocol (OCSP): The certificate for $MESSAGE has been revoked ($reason).\n"
						else
							echo -e "\t\t✖️🔓 Error checking OCSP response: $reason"
							
							error ".cert.ocsp.error$FILE" "❌🔏 Error checking OCSP response for $SUBJECT" "Error checking Online Certificate Status Protocol (OCSP) response for $MESSAGE: $reason.\n"
						fi
						date -u -d "$adate" > "$file"
					else
						echo -e "\t\t✖️🔓 Error querying OCSP responder ($uri): $output"
					fi
				else
					echo "Error: Could not verify certificate chain."
				fi
			else
				echo -e "\t\tℹ OCSP has already been checked since the last update. Next update: $(date -d "$(<"$file")")"
			fi
		fi
	fi
}

# Check certificate expiration
# checkcertificate <certificate>
checkcertificate() {
	local aissuer issuer date sec
	if aissuer=$(echo "$1" | openssl x509 -noout -issuer -nameopt multiline,-align,-esc_msb,utf8,-space_eq); then
		issuer=$(echo "$aissuer" | awk -F'=' '/commonName=/ { print $2 }')
	else
		issuer=''
	fi
	date=$(echo "$1" | openssl x509 -noout -enddate | awk -F'=' '/notAfter=/ { print $2 }')
	if echo "$1" | openssl x509 -noout -checkend 0 > /dev/null; then
		sec=$(( $(date -d "$date" +%s) - $(date -d "$NOW" +%s) ))
		if [[ $(( sec / 86400 )) -lt $WARNDAYS ]]; then
			revocation "$1"
			echo -e "\t\t⚠🔒 Certificate $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expires in ${YELLOW}$(getSecondsAsDigitalClock "$sec")${NC}."
			
			error ".cert.expires$FILE" "⚠️🔏 Certificate for $SUBJECT expires in < $WARNDAYS days" "The certificate for $MESSAGE $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expires in less than $WARNDAYS days ($(date -d "$date")).\n"
		else
			revocation "$1"
			echo -e "\t\t🔒 Certificate $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expires in $(getSecondsAsDigitalClock "$sec")."
			
			noerror ".cert.expires$FILE"
			noerror ".cert.expired$FILE"
		fi
	else
		echo -e "\t\t✖️🔓 Certificate $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expired ${RED}$(date -d "$date")${NC}."
		
		error ".cert.expired$FILE" "❌🔏 Certificate for $SUBJECT expired" "The certificate for $MESSAGE $([[ -n "$issuer" ]] && echo "from “$issuer” " || echo)expired $(date -d "$date").\n"
	fi
}

# Verify TLSA resource record
# tlsa <certificate>
tlsa() {
	local aerror
	if ! aerror=$(echo "$1" | grep -i 'verification error'); then
		echo -e "\t\t✔ DANE TLSA resource record verified."
		
		noerror ".cert.error$FILE"
		checkcertificate "$1"
	else
		aerror=${aerror#*: }
		echo -e "\t\t✖️🔓 Error: Could not verify DANE TLSA resource record with certificate: $aerror"
		
		error ".cert.error$FILE" "❌🔏 Error verifying TLSA RR for $SUBJECT" "Error verifying DANE TLSA Resource Record (RR) with certificate for $MESSAGE: $aerror.\n"
		checkcertificate "$1"
	fi
}

# Verify certificate
# verifycertificate <certificate>
verifycertificate() {
	local aerror
	if ! aerror=$(echo "$1" | grep -i 'verification error'); then
		noerror ".cert.error$FILE"
		checkcertificate "$1"
	else
		aerror=${aerror#*: }
		echo -e "\t\t✖️🔓 Error: Could not verify certificate: $aerror"
		
		error ".cert.error$FILE" "❌🔏 Error verifying certificate for $SUBJECT" "Error verifying certificate for $MESSAGE: $aerror.\n"
		checkcertificate "$1"
	fi
}

# Get certificate
# certificate <hostname> <port> [protocol]
certificate() {
	local data
	# Get TLSA resource record
	# if [[ ! "$1" =~ $IPv4RE && ! "$1" =~ $IPv6RE ]] && if [[ -n "$DNS" ]]; then output=$(dig +dnssec +noall +answer tlsa "_${2}._tcp.${1}" "@$DNS"); else output=$(dig +dnssec +noall +answer tlsa "_${2}._tcp.${1}"); fi && [[ -n "$output" ]] && mapfile -t data < <(echo "$output" | awk '$4 == "TLSA" {print $5, $6, $7, $8, $9}') && [[ -n "$data" ]]; then
	if [[ ! "$1" =~ $IPv4RE && ! "$1" =~ $IPv6RE ]] && if [[ -n "$DNS" ]]; then output=$(delv +noall tlsa "_${2}._tcp.${1}" "@$DNS" 2>&1); else output=$(delv +noall tlsa "_${2}._tcp.${1}" 2>&1); fi && [[ -n "$output" ]] && mapfile -t data < <(echo "$output" | grep -v '^;' | awk '$4 == "TLSA" {print $5, $6, $7, $8, $9}') && [[ -n "$data" ]]; then
		# Check for StartTLS protocol
		if [[ -n "$3" ]]; then
			# Verify TLSA resource record
			if output=$(echo | eval openssl s_client -starttls "$3" -showcerts -connect "$1:$2" -servername "$1" -verify_hostname "$1" -tlsextdebug -status -msg -dane_tlsa_domain "$1" $(printf -- '-dane_tlsa_rrdata "%s" ' "${data[@]}") 2>/dev/null); then
				tlsa "$output"
			else
				echo -e "\t\t✖️ Error: Could not get certificate with StartTLS."
				
				error ".cert.error$FILE" "❌🔏 Error getting certificate for $SUBJECT with StartTLS" "Error getting certificate for $MESSAGE with StartTLS.\n"
			fi
		else
			# Verify TLSA resource record
			if output=$(echo | eval openssl s_client -showcerts -connect "$1:$2" -servername "$1" -verify_hostname "$1" -tlsextdebug -status -msg -dane_tlsa_domain "$1" $(printf -- '-dane_tlsa_rrdata "%s" ' "${data[@]}") 2>/dev/null); then
				tlsa "$output"
			else
				echo -e "\t\t✖️ Error: Could not get certificate: $output"
				
				error ".cert.error$FILE" "❌🔏 Error getting certificate for $SUBJECT" "Error getting certificate for $MESSAGE: $output.\n"
			fi
		fi
	else
		# Check for StartTLS protocol
		if [[ -n "$3" ]]; then
			if output=$(echo | openssl s_client -starttls "$3" -showcerts -connect "$1:$2" -servername "$1" -verify_hostname "$1" -tlsextdebug -status -msg 2>/dev/null); then
				verifycertificate "$output"
			else
				echo -e "\t\t✖️ Error: Could not get certificate with StartTLS."
				
				error ".cert.error$FILE" "❌🔏 Error getting certificate for $SUBJECT with StartTLS" "Error getting certificate for $MESSAGE with StartTLS.\n"
			fi
		else
			if output=$(echo | openssl s_client -showcerts -connect "$1:$2" -servername "$1" -verify_hostname "$1" -tlsextdebug -status -msg 2>/dev/null); then
				verifycertificate "$output"
			fi
		fi
	fi
}

# Domains
DOMAINS=()
# Domain expirations
STATUSES=()

# indexof <array name> <value>
indexof() {
    local -n array=$1
	local index=-1
	for i in "${!array[@]}"; do
        if [[ "${array[$i]}" == "$2" ]]; then
            index=$i
			break
        fi
    done
    echo "$index"
}

# Check domain expiration
# Should work for all TLDs, except for a few which have no whois server (see https://github.com/rfc1036/whois/blob/next/tld_serv_list) or which do not provide the domain expiration date
# checkdomain <hostname>
checkdomain() {
	# Get root domain from Start of Authority (SOA) resource record
	local d index aregistrar registrar adate date sec days
	if [[ ! "$1" =~ $IPv4RE && ! "$1" =~ $IPv6RE ]]; then
		if if [[ -n "$DNS" ]]; then output=$(dig +noall +answer +authority soa "$1" "@$DNS"); else output=$(dig +noall +answer +authority soa "$1"); fi && [[ -n "$output" ]] && d=$(echo "$output" | awk '$4 == "SOA" {print $1}') && [[ -n "$d" ]]; then
			d=${d%.}
			# Only check each domain once an hour for performance and to avoid the whois limit
			if [[ ! -r ".domain.$d" ]] || [[ -r ".domain.$d" && $(( ($(date -d "$NOW" +%s) - $(date -d "$(<".domain.$d")" +%s)) / 3600 )) -gt 0 ]]; then
				index=$(indexof DOMAINS "$d")
				if [[ $index -ge 0 ]]; then
					echo -e "${STATUSES[$index]}"
				else
					local text=''
					# echo "$output" | grep -iq 'no match\|not found\|no data found\|no entries found\|no information\|error\|not satisfy naming rules\|malformed request\|invalid input\|invalid_string\|unassignable\|invalid parameter\|invalid request\|does not exist'
					if output=$(whois "$d" 2>&1) && [[ -n "$output" ]]; then
						# Get Sponsoring Registrar
						# The rest of the TLDs, .uk and .co.uk are on two lines
						if aregistrar=$(echo "$output" | grep -v '^%' | grep -i -A 1 'registrar\.*:\|\[registrant\]\|organization name[[:blank:]]\+\|registrar name:\|record maintained by:\|registrar organization:\|provider:\|support:'); then
							aregistrar=$(echo "$aregistrar" | head -n 2)
							registrar=$(echo "$aregistrar" | sed -n '/^.\+[]:][.[:blank:]]*/ {$!N; s/^[^]:]\+[]:][.[:space:]]*//p}' | head -n 1)
						# .it, on two lines
						elif aregistrar=$(echo "$output" | grep -v '^%' | grep -i -A 1 'registrar'); then
							aregistrar=$(echo "$aregistrar" | head -n 2)
							registrar=$(echo "$aregistrar" | sed -n '/^.\+[[:blank:]]*/ {$!N; s/^[^:]\+[:][[:blank:]]\+//p}' | head -n 1)
						# .dk
						elif aregistrar=$(echo "$output" | grep -i 'copyright (c) [[:print:]]\+ by'); then
							aregistrar=$(echo "$aregistrar" | head -n 1)
							registrar=$(echo "$aregistrar" | sed -n 's/^.\+ by //p')
						# .md, .is, etc. do not provide the domain registrar
						else
							registrar=''
						fi
						# Get Expiration Date
						if adate=$(echo "$output" | grep -i 'expiration\|expires\|expiry\|renewal\|expire\|paid-till\|valid until\|exp date\|vencimiento'); then
							adate=$(echo "$adate" | head -n 1 | sed -n 's/^[^]:]\+[]:][.[:blank:]]*//p')
							# .com.tr
							adate=${adate%.}
							# (The rest of the TLDs) or (.pl) or (.fi and .rs) or (.com.tr, .cz and .pt)
							if date=$(date -u -d "$adate" 2>&1) || date=$(date -u -d "${adate//./-}" 2>&1) || date=$(date -u -d "${adate//.//}" 2>&1) || date=$(date -u -d "$(echo "${adate//./-}" | awk -F'[/-]' '{for(i=NF;i>0;i--) printf "%s%s",$i,(i==1?"\n":"-")}')" 2>&1); then
								sec=$(( $(date -d "$date" +%s) - $(date -d "$NOW" +%s) ))
								days=$(( sec / 86400 ))
								if [[ $days -ge 0 ]]; then
									if [[ $days -lt $WARNDAYS ]]; then
										text="\t\t⚠🌐 Domain ($d) $([[ -n "$registrar" ]] && echo "from “$registrar” " || echo)expires in ${YELLOW}$(getSecondsAsDigitalClock "$sec")${NC}."
										
										error ".domain.expires.$d" "⚠️🌐 Domain $d expires in < $WARNDAYS days" "The domain $d $([[ -n "$registrar" ]] && echo "from “$registrar” " || echo)expires in less than $WARNDAYS days ($(date -d "$date")).\n"
									else
										text="\t\t🌐 Domain ($d) $([[ -n "$registrar" ]] && echo "from “$registrar” " || echo)expires in $(getSecondsAsDigitalClock "$sec")."
										
										noerror ".domain.expires.$d"
										noerror ".domain.expired.$d"
									fi
								else
									text="\t\t✖️🌐 Domain ($d) $([[ -n "$registrar" ]] && echo "from “$registrar” " || echo)expired ${RED}$(date -d "$date")${NC}."
									
									error ".domain.expired.$d" "❌🌐 Domain $d expired" "The domain $d $([[ -n "$registrar" ]] && echo "from “$registrar” " || echo)expired $(date -d "$date").\n"
								fi
							else
								text="\t\tError: Could not input domain expiration date ($adate)."
							fi
						else
							text="\t\tError: Could not get domain expiration date."
						fi
					else
						text="Error querying whois server: ${output#*: }"
					fi
					
					DOMAINS+=("$d")
					STATUSES+=("$text")
					
					echo -e "$text"
					
					# sleep 2
				fi
			else
				echo -e "\t\t🌐ℹ Domain expiration for $d has already been checked in the last hour."
			fi
		else
			echo "Error: Could not get Start of Authority (SOA) resource record: $(echo "$output" | grep '^;;')"
		fi
	fi
}

# Check Blacklist
# checkblacklist <domain> <blacklist> [IP address]
checkblacklist() {
	local answers reasons
	# if if [[ -n "$DNS" ]]; then output=$(dig +short a "$1" "@$DNS"); else output=$(dig +short a "$1"); fi && [[ -n "$output" ]]; then
	if if [[ -n "$DNS" ]]; then output=$(delv +short a "$1" "@$DNS" 2>&1); else output=$(delv +short a "$1" 2>&1); fi && [[ -n "$output" ]] && mapfile -t answers < <(echo "$output" | grep -v '^;') && [[ -n "$answers" ]]; then
		if [[ -n "$DNS" ]]; then output=$(delv +short txt "$1" "@$DNS" 2>&1); else output=$(delv +short txt "$1" 2>&1); fi && [[ -n "$output" ]] && mapfile -t reasons < <(echo "$output" | grep -v '^;')
		echo -e "\t\t⚠🚫 Warning: The $([[ -n "$3" ]] && echo "IP address ($3)" || echo "domain") is listed in the \"$2\" blacklist (${answers[*]})$([[ -n "$reasons" ]] && echo ": ${reasons[*]}" || echo)."
		
		error ".blacklist.$2$FILE" "⚠️🚫 $([[ -n "$3" ]] && echo "IP address ($3)" || echo "Domain") for $SUBJECT is on the \"$2\" blacklist" "The $([[ -n "$3" ]] && echo "IP address ($3)" || echo "domain") for $MESSAGE is listed in the \"$2\" DNS blacklist (${answers[*]})$([[ -n "$reasons" ]] && echo ": ${reasons[*]}" || echo).\n"
	elif output=$(echo "$output" | grep -i '^;; resolution failed') && echo "$output" | grep -iq 'ncache'; then
		noerror ".blacklist.$2$FILE"
	else
		echo "Error: Could not check the the $2 blacklist: ${output#*: }"
	fi
}

# Check Blacklists
# checkblacklists <hostname>
checkblacklists() {
	local bl addresses address reverse
	# Only check each monitor once an hour for performance
	if [[ ! -r ".blacklist$FILE" ]] || [[ -r ".blacklist$FILE" && $(( ($(date -d "$NOW" +%s) - $(date -d "$(<".blacklist$FILE")" +%s)) / 3600 )) -gt 0 ]]; then
		# Check Domain Blacklists
		if [[ ! "$1" =~ $IPv4RE && ! "$1" =~ $IPv6RE ]]; then
			for bl in "${DOMAINBLACKLISTS[@]}"; do
				checkblacklist "$1.$bl" "$bl"
			done
		fi
		# Check IPv4 Blacklists
		if [[ ! "$1" =~ $IPv6RE ]]; then
			addresses=()
			if [[ "$1" =~ $IPv4RE ]]; then
				addresses=( "$1" )
			# if if [[ -n "$DNS" ]]; then output=$(dig +noall +answer a "$1" "@$DNS"); else output=$(dig +noall +answer a "$1"); fi && [[ -n "$output" ]] && mapfile -t addresses < <(echo "$output" | awk '$4 == "A" {print $5}') && [[ -n "$addresses" ]]; then
			elif if [[ -n "$DNS" ]]; then output=$(delv +noall a "$1" "@$DNS" 2>&1); else output=$(delv +noall a "$1" 2>&1); fi && [[ -n "$output" ]]; then
				mapfile -t addresses < <(echo "$output" | grep -v '^;' | awk '$4 == "A" {print $5}')
			elif output=$(echo "$output" | grep -i '^;; resolution failed') && ! echo "$output" | grep -iq 'ncache'; then
				echo "Error: Could not get Address (A) resource record: ${output#*: }"
			fi
			for address in "${addresses[@]}"; do
				# Reverse IPv4 address
				reverse=$(echo "$address" | awk -F'.' '{for(i=NF;i>0;i--) printf "%s%s",$i,(i==1?"\n":".")}')
				for bl in "${IPv4BLACKLISTS[@]}"; do
					checkblacklist "$reverse.$bl" "$bl" "$address"
				done
			done
		fi
		# Check IPv6 Blacklists
		if [[ ! "$1" =~ $IPv4RE ]]; then
			addresses=()
			if [[ "$1" =~ $IPv6RE ]]; then
				addresses=( "$1" )
			# if if [[ -n "$DNS" ]]; then output=$(dig +noall +answer aaaa "$1" "@$DNS"); else output=$(dig +noall +answer aaaa "$1"); fi && [[ -n "$output" ]] && mapfile -t addresses < <(echo "$output" | awk '$4 == "AAAA" {print $5}') && [[ -n "$addresses" ]]; then
			elif if [[ -n "$DNS" ]]; then output=$(delv +noall aaaa "$1" "@$DNS" 2>&1); else output=$(delv +noall aaaa "$1" 2>&1); fi && [[ -n "$output" ]]; then
				mapfile -t addresses < <(echo "$output" | grep -v '^;' | awk '$4 == "AAAA" {print $5}')
			elif output=$(echo "$output" | grep -i '^;; resolution failed') && ! echo "$output" | grep -iq 'ncache'; then
				echo "Error: Could not get IPv6 address (AAAA) resource record: ${output#*: }"
			fi
			for address in "${addresses[@]}"; do
				# Expand and reverse IPv6 address, adapted from: https://gist.github.com/lsowen/4447d916fd19cbb7fce4
				reverse=$(echo "$address" | awk -F: 'BEGIN{OFS="";}{addCount = 9 - NF; for(i=1;i<=NF;i++) {if(length($i) == 0) {for(j=1;j<=addCount;j++) {$i = ($i "0000");}} else{$i = substr(("0000" $i), length($i)+5-4);}}; print}' | awk -F '' 'BEGIN{OFS=".";}{for(i=NF;i>0;i--) printf "%s%s",$i,(i==1?"\n":".")}')
				for bl in "${IPv6BLACKLISTS[@]}"; do
					checkblacklist "$reverse.$bl" "$bl" "$address"
				done
			done
		fi
		
		echo "$NOW" > ".blacklist$FILE"
	else
		echo -e "\t\t🚫ℹ The blacklists have already been checked in the last hour."
	fi
}

# Check visually
# checkvisually <URL>
checkvisually() {
	local message
	if [[ -n "$PERCENTAGE" ]]; then
		# Only take a screenshot of each monitor once an hour for performance
		if [[ ! -r ".visual$FILE" ]] || [[ -r ".visual$FILE" && $(( ($(date -d "$NOW" +%s) - $(date -d "$(<".visual$FILE")" +%s)) / 3600 )) -gt 0 ]]; then
			# Need timeout, since will hang on error: https://developer.mozilla.org/en-US/docs/Mozilla/Firefox/Headless_mode#Taking_screenshots
			if timeout 30 firefox -headless --screenshot "screenshot.png" "$1" > /dev/null 2>&1; then
				if [[ -r "screenshot$FILE.png" ]]; then
					if output=$(compare -metric mae "screenshot.png" "screenshot$FILE.png" null: 2>&1) || [[ $? -eq 1 ]]; then
						output=${output#*(}
						output=${output%)*}
						output=$(echo "$output" | awk '{ printf "%g", $1 * 100 }')
						if (( $(awk 'BEGIN{ print "'"$output"'">="'"$PERCENTAGE"'" }') )); then
							echo -e "\t\t⚠👁 Warning: Visual difference is $output%, which is greater then $PERCENTAGE%."
							message="The visual difference for $MESSAGE is $output%, which is greater than $PERCENTAGE%.\n"
							log "$message"
							send "⚠️👁️ Visual difference for $SUBJECT is > $PERCENTAGE%" "$message\nPlease see attached screenshot.\n" "screenshot.png"
						fi
						rm "screenshot$FILE.png"
					else
						echo "Error comparing screenshots."
					fi
				fi
				mv "screenshot.png" "screenshot$FILE.png"
			else
				echo "Error taking screenshot."
			fi
			
			echo "$NOW" > ".visual$FILE"
		else
			echo -e "\t\t👁ℹ A screenshot has already been taken in the last hour."
		fi
	fi
}

UP=0
DOWN=0

echo -e "${BOLD}Website (HTTP(S)) Monitors${NC}\n"

for i in "${!URLS[@]}"; do
	FILE=".${URLS[$i]//\//}"
	SUBJECT=${WEBSITENAMES[$i]}
	# Remove username and password from URL
	# RE='^((https?:)//)?(([^:]{1,128}):([^@]{1,256})@)?([-.[:alnum:]]{4,253})(:([[:digit:]]{1,5}))?(.*)?$'
	message="${WEBSITENAMES[$i]}"
	# [[ "${URLS[$i]}" =~ $RE ]] && message+=" (${BASH_REMATCH[1]}${BASH_REMATCH[6]}${BASH_REMATCH[7]}${BASH_REMATCH[9]})"
	[[ "${URLS[$i]}" =~ $URLRE ]] && message+=" (${BASH_REMATCH[1]}${BASH_REMATCH[6]}${BASH_REMATCH[31]}${BASH_REMATCH[33]})"
	
	echo -e -n "\t${BOLD}${WEBSITENAMES[$i]}${NC} (${URLS[$i]}"
	
	# if check=$(curl -sILw "%{http_code}\\n" "${URLS[$i]}" -o /dev/null) && [[ $check -ge 200 && $check -lt 300 ]]
	# --retry 1 --retry-connrefused
	if output=$(curl -sSILw "%{url_effective}\\n" "${URLS[$i]}" 2>&1); then
		url=$(echo "$output" | tail -n 1)
		output=$(echo "$output" | head -n -1)
		# Get HTTP status code and reason phrase
		RE='^HTTP/[[:graph:]]+ (([[:digit:]]{3})( [[:print:]]+)?).*$'
		if [[ $(echo "$output" | grep 'HTTP/' | tail -n 1) =~ $RE ]]; then
			reason=${BASH_REMATCH[1]}
			if [[ ${BASH_REMATCH[2]} -ge 200 && ${BASH_REMATCH[2]} -lt 300 ]]; then
				aup=1
			else
				aup=''
			fi
		fi
	else
		aup=''
		reason=$(echo "$output" | head -n 1 | sed -n 's/^[^:]\+: ([^)]\+) //p')
	fi
	
	if [[ -n "$url" && "$url" != "${URLS[$i]}" ]]; then
		echo -n " ⇒ $url) is... "
		# URLS[$i]=$url
	else
		echo -n ") is... "
	fi
	
	if [[ -n "$aup" ]]; then
		echo -e "${GREEN}UP${NC} (${reason})"'!'
		
		if [[ -r "$FILE" ]]; then
			MESSAGE="$message is UP (${reason})"'!'"\n"
			up
		fi
		
		# Get protocol, hostname and port from URL
		# RE='^((https?:)//)?(([^:]{1,128}):([^@]{1,256})@)?([-.[:alnum:]]{4,253})(:([[:digit:]]{1,5}))?(.*)?$'
		if [[ "${URLS[$i]}" =~ $URLRE ]]; then
			protocol=${BASH_REMATCH[2]}
			host=${BASH_REMATCH[6]}
			# Convert hostname to Internationalizing Domain Names in Applications (IDNA) encoding
			# host=$(python -c 'import sys; print unicode(sys.argv[1], "utf8").encode("idna")' "$host")
			MESSAGE="$message"
			dnssec "$host"
			if [[ "$protocol" == "https:" ]]; then
				# port=${BASH_REMATCH[8]:-443}
				port=${BASH_REMATCH[32]:-443}
				certificate "$host" "$port"
			fi
			checkdomain "$host"
			checkblacklists "$host"
		fi
		
		# checkvisually "$url"
		checkvisually "${URLS[$i]}"
		
		((++UP))
	else
		echo -e "${RED}DOWN${NC} (${reason})"'!'
		
		if [[ ! -r "$FILE" ]]; then
			MESSAGE="$message is currently DOWN (${reason})"'!'"\n"
			down
		fi
		
		((++DOWN))
	fi
	
	echo
done

# echo -e "${BOLD}Keyword Website (HTTP(S)) Monitors${NC}\n"

# output=$(curl -sSILw "%{url_effective}\\n" "${URLS[$i]}" 2>&1)
# There is no way with cURL to get the HTTP Headers and Body in separate variables and to have cURL follow redirects without using a temp file or two cURL commands
# I chose to use two commands for performance and to reduce disk ware with SSDs
# output=$(curl -sSL "${URLS[$i]}" 2>&1)

echo -e "${BOLD}Port Monitors${NC}\n"

for i in "${!PORTHOSTNAMES[@]}"; do
	FILE=".${PORTHOSTNAMES[$i]}${PORTS[$i]}"
	SUBJECT=${PORTNAMES[$i]}
	message="${PORTNAMES[$i]} (${PORTHOSTNAMES[$i]}:${PORTS[$i]}$([[ -n "${PROTOCOLS[$i]}" ]] && echo " and Protocol: ${PROTOCOLS[$i]^^}" || echo))"
	
	echo -e -n "\t${BOLD}${PORTNAMES[$i]}${NC} (${PORTHOSTNAMES[$i]}:${PORTS[$i]}$([[ -n "${PROTOCOLS[$i]}" ]] && echo " and Protocol: ${PROTOCOLS[$i]^^}" || echo)) is... "
	
	if output=$(nc -z "${PORTHOSTNAMES[$i]}" "${PORTS[$i]}" 2>&1); then
		aup=1
	else
		aup=''
		reason=$(echo "$output" | sed -n 's/^.\+: //p')
	fi
	
	if [[ -n "$aup" ]]; then
		echo -e "${GREEN}UP${NC}"'!'
		
		if [[ -r "$FILE" ]]; then
			MESSAGE="$message is UP"'!'"\n"
			up
		fi
		
		MESSAGE="$message"
		dnssec "${PORTHOSTNAMES[$i]}"
		certificate "${PORTHOSTNAMES[$i]}" "${PORTS[$i]}" "${PROTOCOLS[$i]}"
		checkdomain "${PORTHOSTNAMES[$i]}"
		checkblacklists "${PORTHOSTNAMES[$i]}"
		
		((++UP))
	else
		echo -e "${RED}DOWN${NC}$([[ -n "$reason" ]] && echo " ($reason)" || echo)"'!'
		
		if [[ ! -r "$FILE" ]]; then
			MESSAGE="$message is currently DOWN$([[ -n "$reason" ]] && echo " ($reason)" || echo)"'!'"\n"
			down
		fi
		
		((++DOWN))
	fi
	
	echo
done

echo -e "${BOLD}Ping Monitors${NC}\n"

for i in "${!PINGHOSTNAMES[@]}"; do
	FILE=".${PINGHOSTNAMES[$i]}"
	SUBJECT=${PORTNAMES[$i]}
	message="${PINGNAMES[$i]} (${PINGHOSTNAMES[$i]})"
	
	echo -e -n "\t${BOLD}${PINGNAMES[$i]}${NC} (${PINGHOSTNAMES[$i]}) is... "
	
	if output=$(ping -q -c 1 "${PINGHOSTNAMES[$i]}" 2>&1); then
		aup=1
	else
		aup=''
		reason=$(echo "$output" | sed -n 's/^.\+: //p')
	fi
	
	if [[ -n "$aup" ]]; then
		echo -e "${GREEN}UP${NC}"'!'
		
		if [[ -r "$FILE" ]]; then
			MESSAGE="$message is UP"'!'"\n"
			up
		fi
		
		MESSAGE="$message"
		dnssec "${PINGHOSTNAMES[$i]}"
		checkdomain "${PINGHOSTNAMES[$i]}"
		checkblacklists "${PINGHOSTNAMES[$i]}"
		
		((++UP))
	else
		echo -e "${RED}DOWN${NC}$([[ -n "$reason" ]] && echo " ($reason)" || echo)"'!'
		
		if [[ ! -r "$FILE" ]]; then
			MESSAGE="$message is currently DOWN$([[ -n "$reason" ]] && echo " ($reason)" || echo)"'!'"\n"
			down
		fi
		
		((++DOWN))
	fi
	
	echo
done

echo -e "${BOLD}Total ${GREEN}█ UP${NC}: $UP\t${BOLD}${RED}█ DOWN${NC}: $DOWN\n"

echo -e "${BOLD}Runtime${NC}: $(getSecondsAsDigitalClock "$SECONDS")\n"

for d in "${DOMAINS[@]}"; do
	echo "$NOW" > ".domain.$d"
done
