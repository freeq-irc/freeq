# Self-contained freeq host, managed by miren

Stand up **one** box that runs its own miren control plane and hosts all of
freeq (server + web + docs), so deployment is entirely under your control — no
shared clusters, no borrowed RBAC. This is the clean replacement for a split
setup across someone else's clusters.

## 1. Sizing (measured, not guessed)

Footprint measured on a live production instance:

| Component | CPU | RAM | Disk |
|---|---|---|---|
| `freeq-server` (IRC + web + REST + AV/iroh, one binary) | <1% of a core | **68 MB** | binary 43 MB; `irc.db` 6.5 MB, media 3.8 MB, policy 0.5 MB |
| `freeq-site` (docs, container) | ~0 | ~120 MB | — |
| **miren control plane** (miren + containerd + shims) | ~0.2 core idle | **~730 MB** | `/var/lib/miren` |

freeq is featherweight; the real drivers are **miren (~1 GB, ~1 core)**, **AV**
(spikes CPU + bandwidth when calls are live, ~1–2 Mbps/stream through the SFU),
and **in-cluster Rust builds** (miren builds the image on the host).

**Recommended: 4 vCPU / 8–16 GB RAM / 160 GB NVMe / ≥10 TB egress.**
Minimum viable: 2 vCPU / 4 GB / 80 GB (tight once miren + a build run together).

## 2. Provider + provision

**Recommended: Hetzner Cloud** — best value and, crucially, generous included
egress for AV; full Terraform/API automation.
- `CCX23` (4 dedicated vCPU / 16 GB / 160 GB, ~20 TB traffic) ≈ €31/mo — this repo's default.
- `CAX21` (4 ARM vCPU / 8 GB) ≈ €8/mo — Rust builds fine on ARM64; cost-first pick.

**DigitalOcean** (you mentioned it) works identically — swap the provider block
in `main.tf` for `digitalocean_droplet` (`s-4vcpu-8gb`, `image = "ubuntu-24-04-x64"`,
`user_data = file("cloud-init.yaml")`) + a `digitalocean_firewall`. `cloud-init.yaml`
is provider-agnostic. DO's egress is stingier (~5 TB pooled, then $0.01/GB), so
Hetzner wins for AV-heavy months.

```bash
cd deploy/new-host
export HCLOUD_TOKEN=...              # token from a NEW Hetzner project for freeq
terraform init
terraform apply \
  -var 'ssh_public_key=<contents of your ~/.ssh/id_ed25519.pub>' \
  -var 'admin_cidrs=["<your.ip>/32"]'      # lock SSH + miren API to you
```

Terraform opens: 80/443 (public — web, WSS IRC, REST, docs, AV-over-WS), 6697
(native IRC-TLS, toggle `expose_native_irc`), UDP 1024–65535 (AV/iroh QUIC), and
22 + 8443 (SSH + miren API, restricted to `admin_cidrs`). cloud-init installs
Docker and pre-pulls `oci.miren.cloud/miren:latest`.

## 3. Bring up miren + register your new org

Create the **new miren organization** for freeq at https://miren.cloud, then on
the host:

```bash
ssh root@<host-ip>
# Register this box as a cluster in YOUR new org (interactive: your org auth):
miren server docker install --host-network --cluster-name freeq-prod
#   …or standalone (no cloud org):  --host-network --without-cloud
```

(The image is already pulled; this just starts it and does the org handshake.
This is the one step that needs your credentials — everything else is scripted.)

From your laptop, add the cluster to your CLI and confirm access:

```bash
miren cluster add -c freeq-prod -a <host-ip>:8443
miren apps -C freeq-prod            # should list nothing yet, NOT 403
```

## 4. Deploy freeq through miren

```bash
# From the repo root:
miren deploy -f -C freeq-prod -a freeq-server -d .            # builds + runs the Rust server
miren deploy -f -C freeq-prod -a freeq-site   -d freeq-site   # docs/site (reuses freeq-site/deploy.sh logic)

# Attach domains (HTTP/WS routes) to the apps:
miren route set freeq.at        -C freeq-prod -a freeq-site
miren route set www.freeq.at    -C freeq-prod -a freeq-site
miren route set irc.freeq.at    -C freeq-prod -a freeq-server
```

Notes:
- **freeq-server exposes non-HTTP ports** (IRC-TLS 6697, AV QUIC/UDP) that
  miren's HTTP router doesn't proxy. For a web-app-only company, WSS via 443 is
  all you need. For native IRC/QUIC, bind those on the host (the container runs
  `--host-network`, so the server's own `--tls-bind 0.0.0.0:6697` and iroh UDP
  are reachable directly through the cloud firewall).
- TLS for the domains is handled by miren's ingress (ACME) once DNS points here.

## 5. Cut over DNS

Point these A records at the new host's IP (from `terraform output ipv4`):

```
freeq.at       A  <host-ip>
www.freeq.at   A  <host-ip>
irc.freeq.at   A  <host-ip>
```

Verify: `https://freeq.at/docs/company-encrypted-channels/` → 200, and
`https://irc.freeq.at/api/v1/health` → 200.

## 6. Back up

`/var/lib/miren` (control-plane state) and the freeq-server data volume
(`irc.db`, `irc-policy.db`, `media/`, and the `*.secret` keys — losing
`db-encryption-key.secret` makes stored messages unreadable). A nightly
`docker exec … sqlite3 VACUUM INTO` + volume snapshot is enough given the tiny
data size.
