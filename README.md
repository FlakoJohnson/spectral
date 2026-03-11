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
               Sweep:    users, computers, groups, gpos, trusts, domain
               Targeted: kerberoastable, asreproast, unconstrained,
                         constrained, rbcd, admincount, shadowcreds,
                         laps, pwdnoexpire, stale, fgpp, adcs
               Shorthand: all (sweep), attack (targeted), everything (both)

  -T  string   Single object lookup: <type>:<name>
               Types: user, computer, group, ou
               Examples:
                 -T user:jdoe
                 -T computer:DC01
                 -T "group:Domain Admins"
                 -T ou:"OU=Servers,DC=corp,DC=local"

  -A  int      Stale threshold in days for -m stale (default: 90)
  -b  string   Base DN (auto-derived from -d if omitted)

Output & pacing:
  -o  string   Output directory (default: ./spectral_output, created if missing)
  -j  int      Jitter between requests in ms (default: 500)
  -P  int      Pause between object types in ms (default: 2000)
  -B  int      Batch size per ADWS pull (default: 100)
  -q           Quiet
  -x           Debug SOAP XML
  -bh          Also write BloodHound CE zip (users/computers/groups/gpos/trusts)

Proxy:
  -proxy string  SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)
                 Also reads ALL_PROXY / SOCKS5_PROXY env vars if flag is omitted.
                 NOTE: proxychains does not work — use this flag instead.
```

## Examples

**Full sweep via SOCKS5 proxy (NTLM PtH):**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m all -o ./out
```

**Attack-path targets only (Kerberos ccache):**
```bash
export KRB5CCNAME=/tmp/jdoe.ccache
export ALL_PROXY=socks5://127.0.0.1:1080
./spectral -t 10.10.10.5 -d corp.local -u jdoe -k -m attack -o ./out
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
  -m attack -j 2000 -P 5000 -B 50 -o ./out
```

**BloodHound CE output:**
```bash
./spectral -proxy socks5://127.0.0.1:1080 -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m all -bh -o ./out
```

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

## OPSEC notes

- Uses `(objectCategory=person)(objectClass=user)` style filters — same as RSAT/PowerShell AD module, not `(!FALSE)`
- GPOs and trusts are scoped to their containers (`CN=Policies,CN=System` / `CN=System`) rather than a full domain sweep
- `kerberoastable` and `asreproast` issue a plain user sweep on the wire and filter client-side — the ADWS log shows `(&(objectCategory=person)(objectClass=user))`, not an SPN/UAC bitmask query. MDI fingerprints `(servicePrincipalName=*)` in the filter as "Possible SPN enumeration via ADWS".
- Configurable jitter and batch size to control query volume
- Binary is built with `-s -w -trimpath` to strip symbols and build paths
- No SDFlags:0x7 pattern (SOAPHound signature)
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

Each mode writes a JSON file to the output directory:

```
out/
├── domain.json
├── users.json
├── computers.json
├── groups.json
├── gpos.json
├── trusts.json
├── kerberoastable.json
├── asreproast.json
└── ...
```

Each file is wrapped with collection metadata:

```json
{
  "collected_at": "2026-03-03T12:00:00Z",
  "count": 42,
  "data": [ ... ]
}
```
