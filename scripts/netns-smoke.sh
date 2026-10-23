#!/bin/sh
# Isolated, root-only integration smoke. No host interfaces, routes, firewall,
# resolver or forwarding settings are changed. Requires Linux network namespaces.
# Usage: sh scripts/netns-smoke.sh [path-to-routertop]
set -eu

[ "$(id -u)" = 0 ] || { echo 'FAIL: root required' >&2; exit 1; }
for tool in ip nft dnsmasq busybox curl timeout sysctl mktemp sed grep; do
    command -v "$tool" >/dev/null || { echo "FAIL: missing $tool" >&2; exit 1; }
done
ROUTERTOP=${1:-routertop}
command -v "$ROUTERTOP" >/dev/null || { echo 'FAIL: routertop binary missing' >&2; exit 1; }
if command -v httpd >/dev/null; then
    HTTPD=$(command -v httpd)
    HTTPD_APPLET=
elif busybox --list | grep -qx httpd; then
    HTTPD=$(command -v busybox)
    HTTPD_APPLET=httpd
else
    echo 'FAIL: BusyBox httpd unavailable; install busybox-extras' >&2
    exit 1
fi
busybox --list | grep -qx udhcpc || { echo 'FAIL: BusyBox udhcpc missing' >&2; exit 1; }
busybox --list | grep -qx nslookup || { echo 'FAIL: BusyBox nslookup missing' >&2; exit 1; }

WORK=$(mktemp -d /tmp/routertop-netns.XXXXXX)
TOKEN=${WORK##*.}
ROUTER=rt-${TOKEN}-r
CLIENT=rt-${TOKEN}-c
WAN=rt-${TOKEN}-w
CREATED=
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$result" != 0 ]; then
        echo "FAIL: namespace smoke exited $result; diagnostic files:" >&2
        for log in "$WORK"/*.log; do
            [ -f "$log" ] || continue
            echo "--- $log" >&2
            tail -n 25 "$log" >&2 || :
        done
    fi
    # Only namespaces successfully created by this invocation are touched.
    for namespace in $CREATED; do
        for process in $(ip netns pids "$namespace" 2>/dev/null); do
            kill "$process" 2>/dev/null || :
        done
    done
    sleep 0.2
    for namespace in $CREATED; do
        for process in $(ip netns pids "$namespace" 2>/dev/null); do
            kill -KILL "$process" 2>/dev/null || :
        done
        ip netns delete "$namespace" 2>/dev/null || :
    done
    # WORK is the exact private directory returned by mktemp above.
    rm -rf -- "$WORK"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
ns() { timeout 15 ip netns exec "$@"; }
pass() { printf 'PASS: %s\n' "$1"; }

for namespace in "$ROUTER" "$CLIENT" "$WAN"; do
    ip netns add "$namespace"
    CREATED="$namespace $CREATED"
    ip -n "$namespace" link set lo up
done
# Create links inside the isolated router namespace, never in the host namespace.
ip -n "$ROUTER" link add wan0 type veth peer name wanpeer
ip -n "$ROUTER" link set wanpeer netns "$WAN"
ip -n "$WAN" link set wanpeer name eth0
ip -n "$ROUTER" link add lan0 type veth peer name lanpeer
ip -n "$ROUTER" link set lanpeer netns "$CLIENT"
ip -n "$CLIENT" link set lanpeer name eth0
ip -n "$ROUTER" address add 198.18.0.2/24 dev wan0
ip -n "$ROUTER" address add 192.168.88.1/24 dev lan0
ip -n "$WAN" address add 198.18.0.1/24 dev eth0
ip -n "$ROUTER" link set wan0 up
ip -n "$ROUTER" link set lan0 up
ip -n "$WAN" link set eth0 up
ip -n "$CLIENT" link set eth0 up

cat >"$WORK/routertop.toml" <<'CONFIG'
hostname = "routertop-smoke"
[wan]
interface = "wan0"
[lan]
interface = "lan0"
address = "192.168.88.1/24"
[dhcp]
start = "192.168.88.100"
end = "192.168.88.199"
lease_hours = 1
[dns]
upstream = ["198.18.0.1"]
[firewall]
https_port = 18080
CONFIG
timeout 15 "$ROUTERTOP" render "$WORK/routertop.toml" --output "$WORK/rendered"
# Only harness lease storage changes; the generated service rules remain intact.
sed "s|^dhcp-leasefile=.*|dhcp-leasefile=$WORK/router.leases|" \
    "$WORK/rendered/dnsmasq.conf" >"$WORK/dnsmasq.conf"
ns "$ROUTER" dnsmasq --test --conf-file="$WORK/dnsmasq.conf"
ns "$ROUTER" nft add table inet unrelated_smoke
ns "$ROUTER" nft add chain inet unrelated_smoke sentinel
ns "$ROUTER" nft add rule inet unrelated_smoke sentinel counter
ns "$ROUTER" nft list table inet unrelated_smoke >"$WORK/unrelated.before"
ns "$ROUTER" nft -c -f "$WORK/rendered/nftables.nft"
ns "$ROUTER" nft -f "$WORK/rendered/nftables.nft"
ns "$ROUTER" nft -f "$WORK/rendered/nftables.nft"
ns "$ROUTER" nft list table inet unrelated_smoke >"$WORK/unrelated.after"
cmp "$WORK/unrelated.before" "$WORK/unrelated.after"
pass 'repeated atomic firewall apply preserves unrelated table'
ns "$ROUTER" sysctl -p "$WORK/rendered/sysctl.conf"
[ "$(ns "$ROUTER" sysctl -n net.ipv4.ip_forward)" = 1 ]
[ "$(ns "$ROUTER" sysctl -n net.ipv6.conf.all.forwarding)" = 0 ]
[ "$(ns "$ROUTER" sysctl -n net.ipv6.conf.default.forwarding)" = 0 ]
pass 'router IPv4 forwarding on; IPv6 forwarding off'

mkdir "$WORK/www"
printf 'routertop-netns-http-ok\n' >"$WORK/www/index.html"
# Empty HTTPD_APPLET intentionally expands to no argument for standalone httpd.
timeout 90 ip netns exec "$WAN" "$HTTPD" ${HTTPD_APPLET:+$HTTPD_APPLET} \
    -f -p 8080 -h "$WORK/www" >"$WORK/wan-http.log" 2>&1 &
timeout 90 ip netns exec "$ROUTER" "$HTTPD" ${HTTPD_APPLET:+$HTTPD_APPLET} \
    -f -p 18080 -h "$WORK/www" >"$WORK/router-http.log" 2>&1 &
timeout 90 ip netns exec "$WAN" dnsmasq --keep-in-foreground --user=root \
    --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
    --interface=eth0 --listen-address=198.18.0.1 \
    --address=/smoke.routertop.test/198.18.0.1 \
    --pid-file="$WORK/wan-dns.pid" >"$WORK/wan-dns.log" 2>&1 &
timeout 90 ip netns exec "$ROUTER" dnsmasq --keep-in-foreground --user=root \
    --conf-file="$WORK/dnsmasq.conf" --pid-file="$WORK/router-dns.pid" \
    >"$WORK/router-dns.log" 2>&1 &

cat >"$WORK/udhcpc-hook" <<'HOOK'
#!/bin/sh
set -eu
case "$1" in
    deconfig) ip address flush dev "$interface" ;;
    bound|renew)
        # Validate this fixture's advertised router and mask before configuring.
        [ "$interface" = eth0 ]
        [ "$subnet" = 255.255.255.0 ]
        [ "${router%% *}" = 192.168.88.1 ]
        [ "${dns%% *}" = 192.168.88.1 ]
        ip address replace "$ip/24" dev "$interface"
        ip route replace default via 192.168.88.1 dev "$interface"
        ;;
esac
HOOK
chmod 700 "$WORK/udhcpc-hook"
sleep 1
timeout 20 ip netns exec "$CLIENT" busybox udhcpc -i eth0 \
    -s "$WORK/udhcpc-hook" -f -n -q -t 5 -T 2 >"$WORK/dhcp.log" 2>&1
ip -n "$CLIENT" -4 address show dev eth0 | grep -Eq 'inet 192\.168\.88\.1[0-9][0-9]/24'
ip -n "$CLIENT" route show default | grep -q 'default via 192.168.88.1'
pass 'LAN client received DHCP address, mask, router and DNS'

ns "$CLIENT" busybox nslookup -type=A smoke.routertop.test 192.168.88.1 >"$WORK/dns.log" 2>&1
grep -q '198.18.0.1' "$WORK/dns.log"
pass 'DNS query forwarded through router to isolated WAN DNS'

# WAN has no route to 192.168.88.0/24: a successful reply requires source NAT.
[ -z "$(ip -n "$WAN" route show 192.168.88.0/24)" ]
ns "$CLIENT" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
    http://198.18.0.1:8080/ >"$WORK/http.log"
grep -qx routertop-netns-http-ok "$WORK/http.log"
pass 'LAN HTTP traverses router and returns through masquerade NAT'

ns "$CLIENT" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
    http://192.168.88.1:18080/ >"$WORK/lan-management.log"
grep -qx routertop-netns-http-ok "$WORK/lan-management.log"
pass 'configured management TCP port accepts LAN clients (plain HTTP test fixture)'

# Prove the listener is alive first, then count WAN packets that fall through
# the input chain to its generated default-drop policy (no added drop verdict).
ns "$ROUTER" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
    http://127.0.0.1:18080/ >"$WORK/listener.log"
grep -qx routertop-netns-http-ok "$WORK/listener.log"
ns "$ROUTER" nft add rule inet routertop input iifname wan0 tcp dport 18080 counter
if ns "$WAN" curl --noproxy '*' --fail --silent --show-error --max-time 3 \
    http://198.18.0.2:18080/ >"$WORK/wan-denial.log" 2>&1; then
    echo 'FAIL: unsolicited WAN TCP reached router listener' >&2
    exit 1
fi
ns "$ROUTER" nft list chain inet routertop input >"$WORK/input.log"
grep -Eq 'tcp dport 18080 counter packets [1-9][0-9]*' "$WORK/input.log"
pass 'unsolicited WAN TCP reaches default-drop policy and is denied'
echo 'PASS: all isolated network namespace integration checks completed'
