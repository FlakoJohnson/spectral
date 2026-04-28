#!/bin/bash

# MDI Evasion Test Script
# Demonstrates different LDAP query patterns and their detection likelihood

echo "🧪 MDI Evasion Test Framework"
echo "=============================="
echo

TARGET="10.10.10.10"
DOMAIN="ludus.domain"
USERNAME="domainuser"
PASSWORD="password"

echo "📋 Test Configuration:"
echo "  Target: $TARGET"
echo "  Domain: $DOMAIN"
echo "  User: $USERNAME"
echo

# Function to run test with timing and logging
run_test() {
    local test_name="$1"
    local command="$2"
    local should_alert="$3"

    echo "🔍 $test_name"
    echo "Command: $command"
    echo "Expected Alert: $should_alert"
    echo "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo

    # Run the command (commented out since labs are down)
    # eval $command

    echo "⏳ Sleeping 30 seconds between tests..."
    echo "---"
    echo
}

echo "🔴 TESTS THAT SHOULD TRIGGER MDI ALERTS:"
echo "========================================"
echo

run_test "Test A1: Direct SPN Enumeration" \
    "./spectral-gopacket -t $TARGET -d $DOMAIN -u $USERNAME -p $PASSWORD -gp -q" \
    "✅ YES - Bulk servicePrincipalName=* detection"

run_test "Test A2: Direct with Verbose" \
    "./spectral-gopacket -t $TARGET -d $DOMAIN -u $USERNAME -p $PASSWORD -gp" \
    "✅ YES - Same pattern with verbose output"

echo "🟢 TESTS THAT SHOULD NOT TRIGGER MDI ALERTS:"
echo "============================================"
echo

run_test "Test B1: Stealth SPN Enumeration" \
    "./spectral-gopacket -t $TARGET -d $DOMAIN -u $USERNAME -p $PASSWORD -gp --gp-stealth -q" \
    "❌ NO - Service-specific queries avoid detection"

run_test "Test B2: Stealth with Normal Enum" \
    "./spectral-gopacket -t $TARGET -d $DOMAIN -u $USERNAME -p $PASSWORD -m users -gp --gp-stealth -q" \
    "❌ NO - Mixed with legitimate enumeration"

run_test "Test B3: Basic User Enumeration Only" \
    "./spectral-gopacket -t $TARGET -d $DOMAIN -u $USERNAME -p $PASSWORD -m users -q" \
    "❌ NO - Standard ADWS enumeration"

echo "🟡 UNCERTAIN TESTS (Need Validation):"
echo "===================================="
echo

run_test "Test C1: AS-REP Roastable Only" \
    "# Custom query: (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    "🟡 MAYBE - Different attack pattern"

run_test "Test C2: Computer Account SPNs" \
    "# Custom query: (&(objectClass=computer)(servicePrincipalName=*))" \
    "🟡 MAYBE - Different object class"

echo "📊 EXPECTED DETECTION PATTERNS:"
echo "==============================="
echo
echo "MDI Triggers:"
echo "  - Filter: (&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))"
echo "  - Scope: WholeSubtree"
echo "  - Attributes: servicePrincipalName + user details"
echo "  - Source: External IP"
echo
echo "Stealth Evasions:"
echo "  - Service-specific filters: servicePrincipalName=HTTP/*"
echo "  - Query timing: 500ms delays between requests"
echo "  - Mixed enumeration: SPN queries + normal user lookups"
echo "  - Alternative methods: adminCount=1, naming patterns"
echo
echo "📝 To run actual tests (when labs are available):"
echo "  1. Uncomment 'eval \$command' lines in run_test function"
echo "  2. Update target/credential variables"
echo "  3. Run: bash test_queries.sh"
echo "  4. Monitor MDI console for alerts"
echo "  5. Compare timestamps with test execution"
echo

echo "✅ Test framework ready for execution!"