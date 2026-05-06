# spectral

ADWS-based Active Directory enumeration tool for Linux. Queries domain controllers over port 9389 (Active Directory Web Services) instead of LDAP, reducing detection surface against common monitoring tools.

Built on top of [sopa](https://github.com/Macmod/sopa).

## Why ADWS

- LDAP traffic never goes over the wire — ADWS proxies it locally on the DC
- MDI does not flag most ADWS queries
- Event 1644 shows `[::1]` as the client (often filtered out)
- Avoids signatures on port 389/636

## Build

```bash
git clone git@github.com:FlakoJohnson/spectral.git
cd spectral
make setup   # vendors deps + applies go-adws proxy patch (run once)
make build
```

Produces a stripped, static `spectral` binary (no CGO, no debug symbols).

> **Re-run `make setup` after `go mod tidy` or any dependency update.**

## Proxy / tunnelling

**proxychains does not work** with this tool. spectral is compiled with `CGO_ENABLED=0`, which means it uses Go's pure-Go network stack and issues TCP connections via direct syscalls — bypassing `libc connect()` entirely. proxychains works by hooking `connect()` via `LD_PRELOAD`, so it never intercepts spectral's connections.

Use the built-in `-proxy` flag (or env vars) instead:

```bash
# SOCKS5 via flag
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 ...

# SOCKS5 via env var (ALL_PROXY / SOCKS5_PROXY are both read)
export ALL_PROXY=socks5://127.0.0.1:1080
./spectral -t 10.10.10.5 ...
```

All traffic — ADWS (port 9389), Kerberos KDC (port 88), and the unauthenticated rootDSE LDAP probe — is routed through the proxy.

## Usage

```
Usage: spectral [options]

Connection:
  -t  string   Target DC address (IP or hostname)
  -d  string   Domain FQDN (e.g. corp.local — NOT the NetBIOS short name)
  -u  string   Username
  -p  string   Password
  -H  string   NT hash (pass-the-hash)
  -k           Use Kerberos (reads KRB5CCNAME env or -c path)
  -c  string   Kerberos ccache path
  -r  string   Port (default: 9389)

Enumeration:
  -m  string   Modes, comma-separated
               Unauthenticated: rootdse
               Sweep:    users, computers, groups, gpos, trusts, ous, domain
               Targeted: kerberoastable, asreproast, unconstrained,
                         constrained, rbcd, admincount, shadowcreds,
                         laps, pwdnoexpire, stale, fgpp, adcs
               Misc:     machinequota
               Shorthand:
                 sweep    — all sweep modes (users, computers, groups, gpos, trusts, ous, domain)
                 targeted — all attack-path modes (kerberoastable, asreproast, delegation, etc.)
                 full     — sweep + targeted combined

  -T  string   Single object lookup: <type>:<name>
               Types: user, computer, group, ou
               Examples:
                 -T user:jdoe
                 -T computer:DC01
                 -T "group:Domain Admins"
                 -T ou:"OU=Servers,DC=corp,DC=local"

  -A  int      Stale threshold in days for -m stale (default: 90)
  -b  string   Base DN (auto-derived from -d if omitted)
               Can be specified multiple times for chunked enumeration:
                 -b "OU=Sales,DC=corp,DC=local" -b "OU=IT,DC=corp,DC=local"

Output & pacing:
  -o  string   Output directory (default: ./<IP>_<YYYYMMDD>/)
  -j  int      Jitter between requests in ms (default: 500)
  -P  int      Pause between object types in ms (default: 2000)
  -B  int      Batch size per ADWS pull (default: 100)
  -q           Quiet
  -x           Debug SOAP XML
  -bh          Also write BloodHound CE zip (auto-generated when sweep data is collected)

Stealth:
  -s           Stealth mode: randomize filters, attrs, batch sizes, query order,
               suppress banner, obfuscate output filenames. Implies -q.
  -Bmin int    Minimum batch size for stealth randomization (default: 75)
  -Bmax int    Maximum batch size for stealth randomization (default: 125)

Proxy:
  -proxy string  SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)
                 Also reads ALL_PROXY / SOCKS5_PROXY env vars if flag is omitted.
                 NOTE: proxychains does not work — use this flag instead.
```

## Examples

**Full sweep via SOCKS5 proxy (NTLM PtH):**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m sweep -o ./out
```

**Attack-path targets only (Kerberos ccache):**
```bash
export KRB5CCNAME=/tmp/jdoe.ccache
export ALL_PROXY=socks5://127.0.0.1:1080
./spectral -t 10.10.10.5 -d corp.local -u jdoe -k -m targeted -o ./out
```

**Single user deep-dive:**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -T user:svc_backup
```

**Kerberoastable accounts only:**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m kerberoastable
```

**Stale accounts (no login in 60 days):**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m stale -A 60
```

**Slower, quieter run with more jitter:**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> \
  -m targeted -j 2000 -P 5000 -B 50 -o ./out
```

**BloodHound CE output (always generated):**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m sweep -o ./out
```

## Sweep modes

The `sweep` shorthand runs: `users`, `computers`, `groups`, `gpos`, `trusts`, `ous`, `domain`.

The `ous` mode enumerates all organizational units with their linked GPOs and GPO link counts. OU data feeds into the BloodHound zip for containment hierarchy.

## Targeted modes

| Mode | What it finds | Wire filter (ADWS log) |
|---|---|---|
| `kerberoastable` | Users with SPNs (excl. krbtgt) | `(&(objectCategory=person)(objectClass=user))` + client-side SPN filter |
| `asreproast` | DONT\_REQUIRE\_PREAUTH users | `(&(objectCategory=person)(objectClass=user))` + client-side UAC filter |
| `unconstrained` | Computers/users with unconstrained delegation (non-DCs) | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| `constrained` | Objects with `msDS-AllowedToDelegateTo` | `(msDS-AllowedToDelegateTo=*)` |
| `rbcd` | Objects with `msDS-AllowedToActOnBehalfOfOtherIdentity` | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` |
| `admincount` | AdminSDHolder-protected objects | `(adminCount=1)` |
| `shadowcreds` | Objects with `msDS-KeyCredentialLink` | `(msDS-KeyCredentialLink=*)` |
| `laps` | Computers with legacy or Windows LAPS | `(ms-Mcs-AdmPwd=*)` / `(msLAPS-Password=*)` |
| `pwdnoexpire` | Enabled users with DONT\_EXPIRE\_PASSWORD | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| `stale` | Enabled users inactive for N days | `(lastLogonTimestamp<=<filetime>)` |
| `fgpp` | Fine-grained password policies (PSOs) | `(objectClass=msDS-PasswordSettings)` |
| `adcs` | AD CS — enterprise CAs, templates, ESC1/2/3/4/6/7/9/15 findings | `(objectClass=pKIcertificateTemplate)` + `(objectClass=pKIEnrollmentService)` |
| `machinequota` | ms-DS-MachineAccountQuota value from domain root | Domain root ADCAP query |

## BloodHound CE output

BloodHound data is automatically generated by default as BH CE v6 zip with full containment hierarchy:

- **ContainedBy edges** — Users, computers, groups, GPOs, and OUs include `ContainedBy` edges linking each object to its parent OU or domain. This enables GPO->OU->object traversal in BloodHound for attack path analysis.
- **OUs and Containers** — OU nodes are included with GPO links and ACLs. Container objects (e.g. `CN=Users`, `CN=Computers`) are auto-collected for accurate placement.
- **Member resolution** — Group member DNs are resolved to SIDs via ADWS before zip generation to avoid orphan DN-stub nodes.
- **ACE principal resolution** — Unknown SIDs in ACEs are resolved to named nodes for inbound object control visibility.
- **Domain ACE processing** — Domain object ACLs are collected and processed for DCSync detection. Identifies AllExtendedRights, DCSync, WriteDacl, and other domain-level privileges essential for privilege escalation analysis.

## Large domain support

For domains with large ADWS responses (e.g. 9600+ computers), two features help avoid "response too large" errors:

**Multiple `-b` flags** — Chunk enumeration by OU scope. Results are merged across all scopes:
```bash
./spectral -t 10.210.96.61 -d amer.corp.local -u svc -p pass \
  -b "OU=East,DC=amer,DC=corp,DC=local" \
  -b "OU=West,DC=amer,DC=corp,DC=local" \
  -m sweep -bh
```

**Split SD fetch for lookups** — `-T` wildcard lookups (e.g. `-T user:*admin*`) first query with `sdFlags=0` (no security descriptors), then re-fetch each matched object individually by DN with `sdFlags=7` for ACL data. This avoids oversized responses on broad searches.

## OPSEC notes

- Uses `(objectCategory=person)(objectClass=user)` style filters — same as RSAT/PowerShell AD module, not `(!FALSE)`
- GPOs and trusts are scoped to their containers (`CN=Policies,CN=System` / `CN=System`) rather than a full domain sweep
- `kerberoastable` and `asreproast` issue a plain user sweep on the wire and filter client-side — the ADWS log shows `(&(objectCategory=person)(objectClass=user))`, not an SPN/UAC bitmask query. MDI fingerprints `(servicePrincipalName=*)` in the filter as "Possible SPN enumeration via ADWS".
- Configurable jitter and batch size to control query volume
- Binary is built with `-s -w -trimpath` to strip symbols and build paths
- SDFlags:0x7 is used selectively (per-object re-fetch and member resolution), not as a bulk sweep pattern like SOAPHound
- **Use Kerberos (`-k`) when possible.** NTLMv2 from a non-domain-joined IP triggers "Suspicious NTLM authentication" in MDI regardless of query content — MDI flags any ADWS NTLMv2 auth where the source resolves to an unknown machine. Running from a domain-joined foothold with a Kerberos ccache avoids this entirely.

## Detection

Confirmed MDI detections observed in testing:

| Alert | Trigger | Mitigation |
|---|---|---|
| Possible SPN enumeration via ADWS | `(servicePrincipalName=*)` in ADWS filter | Fixed — `kerberoastable` now uses a plain user sweep |
| Suspicious NTLM authentication | NTLMv2 over ADWS from a host MDI doesn't recognise | Use Kerberos (`-k`) from a domain-joined pivot |
| Network connection to port 9389 | Any process → DC:9389 | Sigma/Splunk rule — no mitigation at the tool level |
| SACL canary object | Query hits a canary object | Avoid if you know canaries are deployed |
| Event ID 1644 | LDAP query log on DC | Shows `[::1]` as client; commonly filtered by defenders |

## Output

Output is organized for evidence keeping. Directory and filenames include the target IP and date:

```
10.10.10.5_20260324/
├── 10.10.10.5_20260324_domain.json
├── 10.10.10.5_20260324_users.json
├── 10.10.10.5_20260324_computers.json
├── 10.10.10.5_20260324_groups.json
├── 10.10.10.5_20260324_gpos.json
├── 10.10.10.5_20260324_trusts.json
├── 10.10.10.5_20260324_kerberoastable.json
├── 10.10.10.5_20260324_adcs.json
├── 10.10.10.5_20260324_bloodhound.zip
└── ...
```

In stealth mode (`-s`), filenames are obfuscated to SHA256 hashes with a `.manifest.json` for decoding.

Each file is wrapped with collection metadata:

```json
{
  "collected_at": "2026-03-03T12:00:00Z",
  "count": 42,
  "data": [ ... ]
}
```
