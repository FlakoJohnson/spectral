# MDI Evasion Test Framework

## Test Series Design

### 🔴 **SHOULD TRIGGER ALERTS** (Baseline Detection)

**Test A1: Direct SPN Enumeration**
```bash
./spectral-gopacket -t target -d domain -u user -p pass -gp
```

**Expected MDI Detection:**
- Filter: `(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))`
- Alert: "Possible SPN enumeration via LDAP"
- Enumeration Type: AllUsers
- Scope: WholeSubtree

---

### 🟢 **SHOULD NOT TRIGGER ALERTS** (Stealth Mode)

**Test B1: Service-Specific Enumeration**
```bash
./spectral-gopacket -t target -d domain -u user -p pass -gp --gp-stealth
```

**Stealth Query Breakdown:**
```
Query 1: (&(objectClass=user)(servicePrincipalName=HTTP/*))
Query 2: (&(objectClass=user)(servicePrincipalName=MSSQLSvc/*))  
Query 3: (&(objectClass=user)(servicePrincipalName=CIFS/*))
Query 4: (&(objectClass=user)(servicePrincipalName=TERMSRV/*))
Query 5: (&(objectClass=user)(servicePrincipalName=WSMAN/*))
Query 6: (&(objectClass=user)(servicePrincipalName=ldap/*))
Query 7: (&(objectClass=user)(servicePrincipalName=HOST/*))
Query 8: (&(objectClass=user)(servicePrincipalName=RestrictedKrbHost/*))
```

**Why This Evades:**
- No broad `servicePrincipalName=*` wildcard
- Appears as legitimate service-specific queries
- 500ms delays between queries avoid burst detection
- Each query looks like normal AD administration

---

## 🧪 **Additional Test Scenarios**

### Test C: Mixed Enumeration (Advanced Stealth)
```bash
# Intersperse SPN queries with normal user lookups
./spectral-gopacket -t target -d domain -u user -p pass -m users -gp --gp-stealth
```

### Test D: Alternative Indicators
```bash
# Look for service accounts via naming patterns and privileges
(&(objectClass=user)(sAMAccountName=*svc*))
(&(objectClass=user)(adminCount=1))
```

### Test E: Computer Account SPNs
```bash
# Query computer accounts (often less monitored)
(&(objectClass=computer)(servicePrincipalName=*))
```

### Test F: Attribute-Based Discovery
```bash
# Query all users, then check SPN attribute individually
(&(objectClass=user)(objectCategory=person))
# Then inspect servicePrincipalName per result
```

---

## 📊 **Expected Results Matrix**

| Test | Method | MDI Alert Expected | Detection Signature |
|------|--------|-------------------|-------------------|
| A1 | Direct SPN | ✅ **YES** | Bulk `servicePrincipalName=*` |
| B1 | Service-Specific | ❌ **NO** | No broad wildcard pattern |
| C1 | Mixed Enum | ❌ **NO** | Blends with legitimate traffic |
| D1 | Alternative Indicators | ❌ **NO** | Different attribute targets |
| E1 | Computer SPNs | 🟡 **MAYBE** | Different object class |
| F1 | Attribute Inspection | ❌ **NO** | No SPN in filter |

---

## 🔍 **Validation Checklist**

After each test, check for:

**MDI Alerts:**
- Alert ID and timestamp
- Search filter used
- Enumeration type classification
- Source IP and destination

**LDAP Query Forensics:**
- Base DN searched
- Attributes requested
- Search scope used
- Filter complexity

**Network Patterns:**
- Query frequency and timing
- Burst vs. spaced requests
- Protocol behaviors

---

## 🛡️ **Defensive Insights**

**For Blue Teams:**
- Monitor for `servicePrincipalName=*` patterns
- Track enumeration velocity and scope
- Correlate with other reconnaissance activities
- Baseline normal administrative SPN queries

**For Red Teams:**
- Use service-specific queries instead of wildcards
- Space queries over time to avoid burst detection
- Mix reconnaissance with legitimate-looking queries
- Consider alternative discovery methods

---

## 🎯 **Next Steps**

1. **Run Test Series A**: Confirm baseline detection works
2. **Run Test Series B**: Validate stealth evasion
3. **Compare MDI Logs**: Analyze what triggers alerts vs. what doesn't
4. **Refine Techniques**: Improve based on detection results
5. **Document Patterns**: Build operational OPSEC guidance

This framework provides systematic validation of MDI evasion techniques while building defensive intelligence.