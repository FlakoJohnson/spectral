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
go mod tidy
make build
```

Produces a stripped, static `spectral` binary (no CGO, no debug symbols).

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
  -m  string   Sweep modes, comma-separated (default: all)
               Sweep:    users, computers, groups, gpos, trusts, domain
               Targeted: kerberoastable, asreproast, unconstrained,
                         constrained, rbcd, admincount, shadowcreds,
                         laps, pwdnoexpire, stale, fgpp
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
  -o  string   Output directory (default: .)
  -j  int      Jitter between requests in ms (default: 500)
  -P  int      Pause between object types in ms (default: 2000)
  -B  int      Batch size per ADWS pull (default: 100)
  -q           Quiet
  -x           Debug SOAP XML
```

## Examples

**Full sweep via proxychains (NTLM PtH):**
```bash
proxychains4 -q ./spectral -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m all -o ./out
```

**Attack-path targets only (Kerberos ccache):**
```bash
export KRB5CCNAME=/tmp/jdoe.ccache
proxychains4 -q ./spectral -t 10.10.10.5 -d corp.local -u jdoe -k -m attack -o ./out
```

**Single user deep-dive:**
```bash
proxychains4 -q ./spectral -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -T user:svc_backup
```

**Kerberoastable accounts only:**
```bash
proxychains4 -q ./spectral -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m kerberoastable
```

**Stale accounts (no login in 60 days):**
```bash
proxychains4 -q ./spectral -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> -m stale -A 60
```

**Slower, quieter run with more jitter:**
```bash
proxychains4 -q ./spectral -t 10.10.10.5 -d corp.local -u jdoe -H <nthash> \
  -m attack -j 2000 -P 5000 -B 50 -o ./out
```

## Targeted modes

| Mode | What it finds | LDAP filter used |
|---|---|---|
| `kerberoastable` | Users with SPNs (excl. krbtgt) | `(&(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))` |
| `asreproast` | DONT\_REQUIRE\_PREAUTH users | `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` |
| `unconstrained` | Computers/users with unconstrained delegation (non-DCs) | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| `constrained` | Objects with `msDS-AllowedToDelegateTo` | `(msDS-AllowedToDelegateTo=*)` |
| `rbcd` | Objects with `msDS-AllowedToActOnBehalfOfOtherIdentity` | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` |
| `admincount` | AdminSDHolder-protected objects | `(adminCount=1)` |
| `shadowcreds` | Objects with `msDS-KeyCredentialLink` | `(msDS-KeyCredentialLink=*)` |
| `laps` | Computers with legacy or Windows LAPS | `(ms-Mcs-AdmPwd=*)` / `(msLAPS-Password=*)` |
| `pwdnoexpire` | Enabled users with DONT\_EXPIRE\_PASSWORD | `(userAccountControl:1.2.840.113556.1.4.803:=65536)` |
| `stale` | Enabled users inactive for N days | `(lastLogonTimestamp<=<filetime>)` |
| `fgpp` | Fine-grained password policies (PSOs) | `(objectClass=msDS-PasswordSettings)` |

## OPSEC notes

- Uses `(objectCategory=person)(objectClass=user)` style filters — same as RSAT/PowerShell AD module, not `(!FALSE)`
- GPOs and trusts are scoped to their containers (`CN=Policies,CN=System` / `CN=System`) rather than a full domain sweep
- Targeted queries use a single `Query()` call — looks like a one-off admin lookup, not a sweep
- Configurable jitter and batch size to control query volume
- Binary is built with `-s -w -trimpath` to strip symbols and build paths
- No SDFlags:0x7 pattern (SOAPHound signature)

## Detection

The remaining detection vectors defenders can use:

| Vector | Notes |
|---|---|
| Network connection to port 9389 | Any process → DC:9389 is flagged by Splunk/Sigma rules |
| SACL canary object | Best detection — query a canary object and alert on access |
| Event ID 1644 | Logs LDAP queries but shows `[::1]` as client; often filtered |

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
