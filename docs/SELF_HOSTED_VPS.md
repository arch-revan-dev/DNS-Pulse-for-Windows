# Self-Hosted Hardened VPS Guide

DNS Pulse v2.0 includes **`SelfHostedVpsGenerator`** (`DnsPulse.Engine.Discovery`) to generate a production-hardened, private **DoH + DoT + SNI-Proxy** deployment bundle for your own Linux VPS.

> [!IMPORTANT]
> **No Open Resolvers:** `SelfHostedVpsGenerator` strictly rejects empty client lists, `0.0.0.0/0`, `::/0`, and `*`. Every generated deployment enforces **explicit client IP/CIDR allowlisting** at both UFW and `nginx`, plus a **256-bit cryptographic Bearer token** on the DoH endpoint, preventing DNS amplification abuse and unauthorized scanning.

---

## 1. Architecture of the Generated Bundle

```text
Client (DNS Pulse)
   │
   ├──► TCP 443 (nginx stream + ssl_preread)
   │       ├── Allowed CIDR? ──► No  ──► Dropped by UFW & nginx deny all
   │       ├── SNI == your.vps.host  ──► 127.0.0.1:8443 (DoH HTTPS + Bearer Token check)
   │       │                                └──► 127.0.0.1:8053 / CoreDNS 127.0.0.1:5353
   │       └── SNI in TargetGeoUnlockDomains ──► <domain>:443 (Scoped SNI-Proxy)
   │
   └──► TCP 853 (UFW allowlisted CIDRs only)
```

Generated artifacts:
- `docker-compose.yml` — Hardened `coredns/coredns:1.11.3` (`127.0.0.1:5353`, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`) and `nginx:1.27-alpine` (`read_only: true`, `cap_drop: [ALL]`, `cap_add: [NET_BIND_SERVICE]`, `network_mode: host`).
- `nginx.conf` — Stream SNI-proxy + TLS 1.2/1.3 DoH reverse proxy enforcing IP allowlist and `Authorization: Bearer <token>` (returns `403` otherwise).
- `Corefile` — Loopback-bound CoreDNS forwarding upstream over DoT (`tls://1.1.1.1`, `tls://9.9.9.9`) with caching.
- `AdGuardHome.yaml` — Optional drop-in AdGuard Home config (`127.0.0.1:5353`, `ratelimit: 30`, `refuse_any: true`, `allowed_clients` allowlist).
- `ufw-rules.sh` — UFW firewall script denying port `53` globally and allowing `HttpsPort` (`443`) & `DotPort` (`853`) strictly from your allowlisted CIDRs.
- `sdns://` Stamp & `profile.json` — Ready-to-import DNS Pulse profile (`TrustTier.Tier3CustomOrSelfHosted`).

---

## 2. Prerequisites

1. A VPS running Ubuntu 22.04/24.04 or Debian 12 with Docker (`docker compose`) and `ufw`.
2. A domain name (e.g., `dns.example.com`) with an `A` (and optional `AAAA`) record pointing to your VPS IP.
3. Your home/client public IP or CIDR (e.g., `203.0.113.42/32`).

---

## 3. Step-by-Step Deployment

### Step 1: Generate the Bundle in DNS Pulse
In DNS Pulse, open the **Self-Hosted VPS Wizard** (powered by `SelfHostedVpsGenerator`), enter:
- **Hostname:** `dns.example.com`
- **Server IP:** `<your-vps-ip>`
- **Allowed Client CIDRs:** `203.0.113.42/32` (your client IP/subnet)
- **Target Geo-Unlock Domains (optional):** e.g. `gemini.google.com`, `aistudio.google.com`

Save the generated files to a folder (e.g., `~/dnspulse-vps/`) and note the generated **Bearer Token** and **`sdns://...` stamp**.

### Step 2: Obtain a TLS Certificate on the VPS
```bash
sudo apt-get update && sudo apt-get install -y certbot docker.io docker-compose-v2 ufw
sudo certbot certonly --standalone -d dns.example.com

mkdir -p /opt/dnspulse-vps/certs
sudo cp /etc/letsencrypt/live/dns.example.com/fullchain.pem /opt/dnspulse-vps/certs/fullchain.pem
sudo cp /etc/letsencrypt/live/dns.example.com/privkey.pem /opt/dnspulse-vps/certs/privkey.pem
```

### Step 3: Upload Bundle & Apply UFW Firewall
Copy `docker-compose.yml`, `nginx.conf`, `Corefile`, and `ufw-rules.sh` to `/opt/dnspulse-vps/`:

```bash
cd /opt/dnspulse-vps
chmod +x ufw-rules.sh
sudo ./ufw-rules.sh
```

Verify UFW status (`53` denied, `443/tcp` & `853/tcp` open only to your allowlisted CIDRs):
```bash
sudo ufw status verbose
```

### Step 4: Start the Stack
```bash
cd /opt/dnspulse-vps
sudo docker compose up -d
sudo docker compose ps
```

*(Note: If using `AdGuardHome` on `127.0.0.1:8053` behind `nginx` as configured in `nginx.conf` `proxy_pass http://127.0.0.1:8053/dns-query`, ensure your DoH backend listens on `127.0.0.1:8053` or point `nginx.conf` to your chosen local DoH service.)*

### Step 5: Import the `sdns://` Stamp into DNS Pulse
1. Copy the generated **`sdns://...`** DNSCrypt v2 DoH stamp (or `profile.json`) into **DNS Pulse → Add Server / Import Stamp**.
2. DNS Pulse automatically decodes the protocol (`DoH`), `DnsSec | NoLog | NoFilter` flags, bootstrap IP, SNI hostname, DoH path (`/dns-query`), and optional certificate SHA-256 hash (`CertificateSha256Hash`) via `DnsStampCodec.Parse`.
3. Configure the generated `Authorization: Bearer <token>` header in the profile's HTTP headers, run the **6-Layer Availability Doctor** to verify `DiagnosticVerdict.Healthy`, and assign the node to **Zone 3** (Geo-Unlock) or **Zone 4** (Self-Hosted Encrypted).
