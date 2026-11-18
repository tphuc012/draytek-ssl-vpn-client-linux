#!/bin/bash
# Add a route through the VPN for each IP in the list.
# Usage: bash vpn-add.sh            (defaults to utun4)
#        bash vpn-add.sh utun5      (if the VPN interface name changes)

IFACE=${1:-utun4}

IPS=(
  # add IPs here, one per line
)

for ip in "${IPS[@]}"; do
  sudo route -n add -host "$ip" -interface "$IFACE"
done
