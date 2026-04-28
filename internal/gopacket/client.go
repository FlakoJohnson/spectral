package gopacket

import (
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
)

// Client wraps gopacket-style functionality for spectral integration
// This provides impacket-style enumeration using standard Go LDAP
type Client struct {
	host        string
	port        int
	domain      string
	username    string
	password    string
	useKerberos bool
	verbose     bool

	// Protocol clients
	ldapConn *ldap.Conn
}

// Config holds gopacket client configuration
type Config struct {
	Host        string
	Port        int
	Domain      string
	Username    string
	Password    string
	Verbose     bool
	UseKerberos bool
}

// NewClient creates a new gopacket-style client for AD enumeration
func NewClient(cfg Config) *Client {
	return &Client{
		host:        cfg.Host,
		port:        cfg.Port,
		domain:      cfg.Domain,
		username:    cfg.Username,
		password:    cfg.Password,
		useKerberos: cfg.UseKerberos,
		verbose:     cfg.Verbose,
	}
}

// Connect establishes connections to target using standard LDAP
func (c *Client) Connect() error {
	if c.verbose {
		log.Printf("[*] Connecting to %s:%d with impacket-style enumeration", c.host, c.port)
	}

	// Set default port
	if c.port == 0 {
		c.port = 389
	}

	// Establish LDAP connection
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", addr))
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %v", err)
	}
	c.ldapConn = conn

	// Authenticate
	bindUser := c.username
	if c.domain != "" {
		bindUser = fmt.Sprintf("%s\\%s", c.domain, c.username)
	}

	err = c.ldapConn.Bind(bindUser, c.password)
	if err != nil {
		c.ldapConn.Close()
		return fmt.Errorf("LDAP authentication failed: %v", err)
	}

	if c.verbose {
		log.Printf("[+] Connected via LDAP (impacket-style)")
	}

	return nil
}

// getBaseDN gets the default naming context from RootDSE
func (c *Client) getBaseDN() (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := c.ldapConn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("could not retrieve RootDSE")
	}

	return sr.Entries[0].GetAttributeValue("defaultNamingContext"), nil
}

// EnumerateUsers uses standard LDAP to enumerate domain users
func (c *Client) EnumerateUsers() ([]map[string]interface{}, error) {
	if c.ldapConn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	baseDN, err := c.getBaseDN()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain naming context: %v", err)
	}

	filter := "(&(objectClass=user)(objectCategory=person))"
	attributes := []string{
		"distinguishedName", "sAMAccountName", "userPrincipalName",
		"displayName", "description", "objectSid", "whenCreated",
		"lastLogon", "pwdLastSet", "adminCount", "userAccountControl",
	}

	if c.verbose {
		log.Printf("[*] Searching for users in %s", baseDN)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.ldapConn.SearchWithPaging(searchRequest, 1000)
	if err != nil {
		return nil, fmt.Errorf("user enumeration failed: %v", err)
	}

	users := make([]map[string]interface{}, 0, len(result.Entries))
	for _, entry := range result.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				user[attr.Name] = attr.Values[0]
			} else {
				user[attr.Name] = attr.Values
			}
		}
		users = append(users, user)
	}

	if c.verbose {
		log.Printf("[+] Enumerated %d users via impacket-style LDAP", len(users))
	}

	return users, nil
}

// EnumerateComputers uses standard LDAP to enumerate domain computers
func (c *Client) EnumerateComputers() ([]map[string]interface{}, error) {
	if c.ldapConn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	baseDN, err := c.getBaseDN()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain naming context: %v", err)
	}

	filter := "(objectClass=computer)"
	attributes := []string{
		"distinguishedName", "sAMAccountName", "dNSHostName",
		"operatingSystem", "operatingSystemVersion", "description",
		"objectSid", "whenCreated", "lastLogon", "userAccountControl",
	}

	if c.verbose {
		log.Printf("[*] Searching for computers in %s", baseDN)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.ldapConn.SearchWithPaging(searchRequest, 1000)
	if err != nil {
		return nil, fmt.Errorf("computer enumeration failed: %v", err)
	}

	computers := make([]map[string]interface{}, 0, len(result.Entries))
	for _, entry := range result.Entries {
		computer := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				computer[attr.Name] = attr.Values[0]
			} else {
				computer[attr.Name] = attr.Values
			}
		}
		computers = append(computers, computer)
	}

	if c.verbose {
		log.Printf("[+] Enumerated %d computers via impacket-style LDAP", len(computers))
	}

	return computers, nil
}

// EnumerateGroups uses standard LDAP to enumerate domain groups
func (c *Client) EnumerateGroups() ([]map[string]interface{}, error) {
	if c.ldapConn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	baseDN, err := c.getBaseDN()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain naming context: %v", err)
	}

	filter := "(objectClass=group)"
	attributes := []string{
		"distinguishedName", "sAMAccountName", "name",
		"description", "objectSid", "whenCreated",
		"groupType", "adminCount", "member",
	}

	if c.verbose {
		log.Printf("[*] Searching for groups in %s", baseDN)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.ldapConn.SearchWithPaging(searchRequest, 1000)
	if err != nil {
		return nil, fmt.Errorf("group enumeration failed: %v", err)
	}

	groups := make([]map[string]interface{}, 0, len(result.Entries))
	for _, entry := range result.Entries {
		group := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				group[attr.Name] = attr.Values[0]
			} else {
				group[attr.Name] = attr.Values
			}
		}
		groups = append(groups, group)
	}

	if c.verbose {
		log.Printf("[+] Enumerated %d groups via impacket-style LDAP", len(groups))
	}

	return groups, nil
}

// EnumerateKerberoastable finds users with SPNs (Kerberoastable accounts)
func (c *Client) EnumerateKerberoastable() ([]map[string]interface{}, error) {
	if c.ldapConn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	baseDN, err := c.getBaseDN()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain naming context: %v", err)
	}

	filter := "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))"
	attributes := []string{
		"distinguishedName", "sAMAccountName", "servicePrincipalName",
		"userPrincipalName", "displayName", "lastLogon", "pwdLastSet",
	}

	if c.verbose {
		log.Printf("[*] Searching for Kerberoastable users in %s", baseDN)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.ldapConn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("Kerberoastable enumeration failed: %v", err)
	}

	users := make([]map[string]interface{}, 0, len(result.Entries))
	for _, entry := range result.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				user[attr.Name] = attr.Values[0]
			} else {
				user[attr.Name] = attr.Values
			}
		}
		users = append(users, user)
	}

	if c.verbose {
		log.Printf("[+] Found %d Kerberoastable users via impacket-style LDAP", len(users))
	}

	return users, nil
}

// EnumerateASREPRoastable finds users with DONT_REQUIRE_PREAUTH set
func (c *Client) EnumerateASREPRoastable() ([]map[string]interface{}, error) {
	if c.ldapConn == nil {
		return nil, fmt.Errorf("LDAP connection not established")
	}

	baseDN, err := c.getBaseDN()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain naming context: %v", err)
	}

	// DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
	filter := "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{
		"distinguishedName", "sAMAccountName", "userPrincipalName",
		"displayName", "userAccountControl", "lastLogon", "pwdLastSet",
	}

	if c.verbose {
		log.Printf("[*] Searching for AS-REP Roastable users in %s", baseDN)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.ldapConn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("AS-REP Roastable enumeration failed: %v", err)
	}

	users := make([]map[string]interface{}, 0, len(result.Entries))
	for _, entry := range result.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if len(attr.Values) == 1 {
				user[attr.Name] = attr.Values[0]
			} else {
				user[attr.Name] = attr.Values
			}
		}
		users = append(users, user)
	}

	if c.verbose {
		log.Printf("[+] Found %d AS-REP Roastable users via impacket-style LDAP", len(users))
	}

	return users, nil
}

// EnumerateShares placeholder for SMB share enumeration
func (c *Client) EnumerateShares() ([]string, error) {
	// TODO: Implement SMB share enumeration
	shares := make([]string, 0)

	if c.verbose {
		log.Printf("[+] SMB share enumeration not yet implemented")
	}

	return shares, nil
}

// Close cleans up connections
func (c *Client) Close() error {
	if c.ldapConn != nil {
		c.ldapConn.Close()
	}
	if c.verbose {
		log.Printf("[-] Closed impacket-style connections")
	}
	return nil
}