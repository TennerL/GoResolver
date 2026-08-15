# Transparent Proxy (Ubuntu 22.04)

This enables nginx to preserve the original client IP at L3 when proxying to your backend. It requires OS routing changes and nginx to bind with `transparent`.

Important:
- Transparent proxy requires `cap_net_admin` on the nginx binary. This works best with file capabilities (`setcap`) on ext4.
- Systemd ambient capabilities are fragile on some hosts and can cause nginx worker failures (`capset()` errors). Prefer file capabilities.
- If transparent proxy cannot be stabilized, disable it and rely on `X-Forwarded-For` instead.

## 1) Enable transparent mode in GoResolver
- Set `nginx.transparent_proxy` to `1` (in settings UI or DB).
- Redeploy nginx config via the app (any config save triggers deploy).

Result: nginx will emit `proxy_bind $remote_addr transparent;` in each `location /` block.

## 2) Kernel sysctls
```bash
sudo sysctl -w net.ipv4.ip_nonlocal_bind=1
sudo sysctl -w net.ipv4.ip_forward=1
```

Persist:
```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-gresolver-transparent.conf
net.ipv4.ip_nonlocal_bind=1
net.ipv4.ip_forward=1
EOF
sudo sysctl --system
```

## 3) Allow nginx to use transparent sockets (recommended: file caps)
Ensure the nginx binary is on a filesystem that supports file capabilities (ext4).
```bash
df -T "$(command -v nginx)"
```

Apply file capabilities:
```bash
sudo setcap 'cap_net_admin,cap_net_bind_service=+ep' "$(command -v nginx)"
getcap "$(command -v nginx)"
sudo systemctl restart nginx
```

Avoid systemd ambient caps unless you know they work on your host. Some kernels/hosts will fail with
`capset()` errors when using ambient caps.

## 4) Policy routing for transparent proxy replies
This ensures packets destined to client IPs are treated as local so nginx can forward them.

```bash
sudo ip rule add fwmark 1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
```

Persist (Ubuntu):
```bash
cat <<'EOF' | sudo tee /etc/systemd/system/gresolver-tproxy-routes.service
[Unit]
Description=GoResolver transparent proxy policy routing
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/ip rule add fwmark 1 lookup 100
ExecStart=/sbin/ip route add local 0.0.0.0/0 dev lo table 100
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now gresolver-tproxy-routes
```

## 5) iptables mangle rules
```bash
sudo iptables -t mangle -N DIVERT

sudo iptables -t mangle -A PREROUTING \
    -p tcp \
    -m socket --transparent \
    -j DIVERT

sudo iptables -t mangle -A DIVERT \
    -j MARK --set-mark 1

sudo iptables -t mangle -A DIVERT \
    -j ACCEPT

sudo ip rule add fwmark 1 lookup 100

sudo ip route add local 0.0.0.0/0 dev lo table 100
```

Persist (choose one):
- `iptables-persistent`, or
- save/restore with your config management.

## 6) Backend routing requirement
Your backend must return traffic to this nginx host as its default gateway over the VPN (`tun0`). Otherwise responses will bypass nginx and the connection will fail.

## 7) Verify
- Generate traffic and confirm backend sees client IP at L3.
- Check nginx error log for `transparent` or `nonlocal` bind errors.

## 8) Fallback (no transparent proxy)
If transparent proxy is unstable on your host:
1. Set `nginx.transparent_proxy` to `0`.
2. Remove `proxy_bind ... transparent` from site configs.
3. Use `X-Forwarded-For` in the app and in fail2ban/DDoS logic.
