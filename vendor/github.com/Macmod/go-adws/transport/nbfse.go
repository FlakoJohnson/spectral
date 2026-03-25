package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

type nbfxNode struct {
	Prefix   string
	Name     string
	Attrs    []nbfxAttr
	Children []*nbfxNode
	Text     string
}

type nbfxAttr struct {
	Prefix  string
	Name    string
	Value   string
	IsXMLNS bool
}

var knownNSPrefix = map[string]string{
	"http://www.w3.org/2003/05/soap-envelope":                               "s",
	"http://www.w3.org/2005/08/addressing":                                  "a",
	"http://schemas.xmlsoap.org/ws/2004/09/enumeration":                     "wsen",
	"http://schemas.xmlsoap.org/ws/2004/09/transfer":                        "wst",
	"http://schemas.microsoft.com/2008/1/ActiveDirectory":                   "ad",
	"http://schemas.microsoft.com/2008/1/ActiveDirectory/Data":              "addata",
	"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery": "adlq",
	"http://www.w3.org/2001/XMLSchema-instance":                             "xsi",
	"http://www.w3.org/2001/XMLSchema":                                      "xsd",
}

// nbfxDict is the complete NBFS static dictionary as defined in [MC-NBFS] section 2.1.
// Even IDs map to these strings; odd IDs are NBFSE dynamic StringTable entries.
var nbfxDict = map[int]string{
	0x000: "mustUnderstand",
	0x002: "Envelope",
	0x004: "http://www.w3.org/2003/05/soap-envelope",
	0x006: "http://www.w3.org/2005/08/addressing",
	0x008: "Header",
	0x00A: "Action",
	0x00C: "To",
	0x00E: "Body",
	0x010: "Algorithm",
	0x012: "RelatesTo",
	0x014: "http://www.w3.org/2005/08/addressing/anonymous",
	0x016: "URI",
	0x018: "Reference",
	0x01A: "MessageID",
	0x01C: "Id",
	0x01E: "Identifier",
	0x020: "http://schemas.xmlsoap.org/ws/2005/02/rm",
	0x022: "Transforms",
	0x024: "Transform",
	0x026: "DigestMethod",
	0x028: "DigestValue",
	0x02A: "Address",
	0x02C: "ReplyTo",
	0x02E: "SequenceAcknowledgement",
	0x030: "AcknowledgementRange",
	0x032: "Upper",
	0x034: "Lower",
	0x036: "BufferRemaining",
	0x038: "http://schemas.microsoft.com/ws/2006/05/rm",
	0x03A: "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement",
	0x03C: "SecurityTokenReference",
	0x03E: "Sequence",
	0x040: "MessageNumber",
	0x042: "http://www.w3.org/2000/09/xmldsig#",
	0x044: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
	0x046: "KeyInfo",
	0x048: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
	0x04A: "http://www.w3.org/2001/04/xmlenc#",
	0x04C: "http://schemas.xmlsoap.org/ws/2005/02/sc",
	0x04E: "DerivedKeyToken",
	0x050: "Nonce",
	0x052: "Signature",
	0x054: "SignedInfo",
	0x056: "CanonicalizationMethod",
	0x058: "SignatureMethod",
	0x05A: "SignatureValue",
	0x05C: "DataReference",
	0x05E: "EncryptedData",
	0x060: "EncryptionMethod",
	0x062: "CipherData",
	0x064: "CipherValue",
	0x066: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	0x068: "Security",
	0x06A: "Timestamp",
	0x06C: "Created",
	0x06E: "Expires",
	0x070: "Length",
	0x072: "ReferenceList",
	0x074: "ValueType",
	0x076: "Type",
	0x078: "EncryptedHeader",
	0x07A: "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd",
	0x07C: "RequestSecurityTokenResponseCollection",
	0x07E: "http://schemas.xmlsoap.org/ws/2005/02/trust",
	0x080: "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret",
	0x082: "http://schemas.microsoft.com/ws/2006/02/transactions",
	0x084: "s",
	0x086: "Fault",
	0x088: "MustUnderstand",
	0x08A: "role",
	0x08C: "relay",
	0x08E: "Code",
	0x090: "Reason",
	0x092: "Text",
	0x094: "Node",
	0x096: "Role",
	0x098: "Detail",
	0x09A: "Value",
	0x09C: "Subcode",
	0x09E: "NotUnderstood",
	0x0A0: "qname",
	// 0x0A2 is reserved (no mapping in the spec)
	0x0A4: "From",
	0x0A6: "FaultTo",
	0x0A8: "EndpointReference",
	0x0AA: "PortType",
	0x0AC: "ServiceName",
	0x0AE: "PortName",
	0x0B0: "ReferenceProperties",
	0x0B2: "RelationshipType",
	0x0B4: "Reply",
	0x0B6: "a",
	0x0B8: "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity",
	0x0BA: "Identity",
	0x0BC: "Spn",
	0x0BE: "Upn",
	0x0C0: "Rsa",
	0x0C2: "Dns",
	0x0C4: "X509v3Certificate",
	0x0C6: "http://www.w3.org/2005/08/addressing/fault",
	0x0C8: "ReferenceParameters",
	0x0CA: "IsReferenceParameter",
	0x0CC: "http://www.w3.org/2005/08/addressing/reply",
	0x0CE: "http://www.w3.org/2005/08/addressing/none",
	0x0D0: "Metadata",
	0x0D2: "http://schemas.xmlsoap.org/ws/2004/08/addressing",
	0x0D4: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
	0x0D6: "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault",
	0x0D8: "http://schemas.xmlsoap.org/ws/2004/06/addressingex",
	0x0DA: "RedirectTo",
	0x0DC: "Via",
	0x0DE: "http://www.w3.org/2001/10/xml-exc-c14n#",
	0x0E0: "PrefixList",
	0x0E2: "InclusiveNamespaces",
	0x0E4: "ec",
	0x0E6: "SecurityContextToken",
	0x0E8: "Generation",
	0x0EA: "Label",
	0x0EC: "Offset",
	0x0EE: "Properties",
	0x0F0: "Cookie",
	0x0F2: "wsc",
	0x0F4: "http://schemas.xmlsoap.org/ws/2004/04/sc",
	0x0F6: "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk",
	0x0F8: "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct",
	0x0FA: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT",
	0x0FC: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT",
	0x0FE: "RenewNeeded",
	0x100: "BadContextToken",
	0x102: "c",
	0x104: "http://schemas.xmlsoap.org/ws/2005/02/sc/dk",
	0x106: "http://schemas.xmlsoap.org/ws/2005/02/sc/sct",
	0x108: "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT",
	0x10A: "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT",
	0x10C: "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew",
	0x10E: "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew",
	0x110: "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel",
	0x112: "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel",
	0x114: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
	0x116: "http://www.w3.org/2001/04/xmlenc#kw-aes128",
	0x118: "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
	0x11A: "http://www.w3.org/2001/04/xmlenc#kw-aes192",
	0x11C: "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
	0x11E: "http://www.w3.org/2001/04/xmlenc#kw-aes256",
	0x120: "http://www.w3.org/2001/04/xmlenc#des-cbc",
	0x122: "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
	0x124: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
	0x126: "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
	0x128: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
	0x12A: "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1",
	0x12C: "http://www.w3.org/2001/04/xmlenc#ripemd160",
	0x12E: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	0x130: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
	0x132: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	0x134: "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
	0x136: "http://www.w3.org/2000/09/xmldsig#sha1",
	0x138: "http://www.w3.org/2001/04/xmlenc#sha256",
	0x13A: "http://www.w3.org/2001/04/xmlenc#sha512",
	0x13C: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
	0x13E: "http://www.w3.org/2001/04/xmlenc#kw-tripledes",
	0x140: "http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap",
	0x142: "http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap",
	0x144: "http://schemas.microsoft.com/ws/2006/05/security",
	0x146: "dnse",
	0x148: "o",
	0x14A: "Password",
	0x14C: "PasswordText",
	0x14E: "Username",
	0x150: "UsernameToken",
	0x152: "BinarySecurityToken",
	0x154: "EncodingType",
	0x156: "KeyIdentifier",
	0x158: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security1.0#Base64Binary",
	0x15A: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary",
	0x15C: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text",
	0x15E: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile1.0#X509SubjectKeyIdentifier",
	0x160: "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ",
	0x162: "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile1.1#GSS_Kerberosv5_AP_REQ1510",
	0x164: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID",
	0x166: "Assertion",
	0x168: "urn:oasis:names:tc:SAML:1.0:assertion",
	0x16A: "http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license",
	0x16C: "FailedAuthentication",
	0x16E: "InvalidSecurityToken",
	0x170: "InvalidSecurity",
	0x172: "k",
	0x174: "SignatureConfirmation",
	0x176: "TokenType",
	0x178: "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1",
	0x17A: "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey",
	0x17C: "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1",
	0x17E: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1",
	0x180: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
	0x182: "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID",
	0x184: "AUTH-HASH",
	0x186: "RequestSecurityTokenResponse",
	0x188: "KeySize",
	0x18A: "RequestedTokenReference",
	0x18C: "AppliesTo",
	0x18E: "Authenticator",
	0x190: "CombinedHash",
	0x192: "BinaryExchange",
	0x194: "Lifetime",
	0x196: "RequestedSecurityToken",
	0x198: "Entropy",
	0x19A: "RequestedProofToken",
	0x19C: "ComputedKey",
	0x19E: "RequestSecurityToken",
	0x1A0: "RequestType",
	0x1A2: "Context",
	0x1A4: "BinarySecret",
	0x1A6: "http://schemas.xmlsoap.org/ws/2005/02/trust/spnego",
	0x1A8: "http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego",
	0x1AA: "wst",
	0x1AC: "http://schemas.xmlsoap.org/ws/2004/04/trust",
	0x1AE: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue",
	0x1B0: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue",
	0x1B2: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue",
	0x1B4: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1",
	0x1B6: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey",
	0x1B8: "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce",
	0x1BA: "KeyType",
	0x1BC: "http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey",
	0x1BE: "http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey",
	0x1C0: "Claims",
	0x1C2: "InvalidRequest",
	0x1C4: "RequestFailed",
	0x1C6: "SignWith",
	0x1C8: "EncryptWith",
	0x1CA: "EncryptionAlgorithm",
	0x1CC: "CanonicalizationAlgorithm",
	0x1CE: "ComputedKeyAlgorithm",
	0x1D0: "UseKey",
	0x1D2: "http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego",
	0x1D4: "http://schemas.microsoft.com/net/2004/07/secext/TLSNego",
	0x1D6: "t",
	0x1D8: "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
	0x1DA: "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue",
	0x1DC: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
	0x1DE: "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey",
	0x1E0: "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1",
	0x1E2: "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce",
	0x1E4: "RenewTarget",
	0x1E6: "CancelTarget",
	0x1E8: "RequestedTokenCancelled",
	0x1EA: "RequestedAttachedReference",
	0x1EC: "RequestedUnattachedReference",
	0x1EE: "IssuedTokens",
	0x1F0: "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew",
	0x1F2: "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel",
	0x1F4: "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey",
	0x1F6: "Access",
	0x1F8: "AccessDecision",
	0x1FA: "Advice",
	0x1FC: "AssertionID",
	0x1FE: "AssertionIDReference",
	0x200: "Attribute",
	0x202: "AttributeName",
	0x204: "AttributeNamespace",
	0x206: "AttributeStatement",
	0x208: "AttributeValue",
	0x20A: "Audience",
	0x20C: "AudienceRestrictionCondition",
	0x20E: "AuthenticationInstant",
	0x210: "AuthenticationMethod",
	0x212: "AuthenticationStatement",
	0x214: "AuthorityBinding",
	0x216: "AuthorityKind",
	0x218: "AuthorizationDecisionStatement",
	0x21A: "Binding",
	0x21C: "Condition",
	0x21E: "Conditions",
	0x220: "Decision",
	0x222: "DoNotCacheCondition",
	0x224: "Evidence",
	0x226: "IssueInstant",
	0x228: "Issuer",
	0x22A: "Location",
	0x22C: "MajorVersion",
	0x22E: "MinorVersion",
	0x230: "NameIdentifier",
	0x232: "Format",
	0x234: "NameQualifier",
	0x236: "Namespace",
	0x238: "NotBefore",
	0x23A: "NotOnOrAfter",
	0x23C: "saml",
	0x23E: "Statement",
	0x240: "Subject",
	0x242: "SubjectConfirmation",
	0x244: "SubjectConfirmationData",
	0x246: "ConfirmationMethod",
	0x248: "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key",
	0x24A: "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches",
	0x24C: "SubjectLocality",
	0x24E: "DNSAddress",
	0x250: "IPAddress",
	0x252: "SubjectStatement",
	0x254: "urn:oasis:names:tc:SAML:1.0:am:unspecified",
	0x256: "xmlns",
	0x258: "Resource",
	0x25A: "UserName",
	0x25C: "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
	0x25E: "EmailName",
	0x260: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	0x262: "u",
	0x264: "ChannelInstance",
	0x266: "http://schemas.microsoft.com/ws/2005/02/duplex",
	0x268: "Encoding",
	0x26A: "MimeType",
	0x26C: "CarriedKeyName",
	0x26E: "Recipient",
	0x270: "EncryptedKey",
	0x272: "KeyReference",
	0x274: "e",
	0x276: "http://www.w3.org/2001/04/xmlenc#Element",
	0x278: "http://www.w3.org/2001/04/xmlenc#Content",
	0x27A: "KeyName",
	0x27C: "MgmtData",
	0x27E: "KeyValue",
	0x280: "RSAKeyValue",
	0x282: "Modulus",
	0x284: "Exponent",
	0x286: "X509Data",
	0x288: "X509IssuerSerial",
	0x28A: "X509IssuerName",
	0x28C: "X509SerialNumber",
	0x28E: "X509Certificate",
	0x290: "AckRequested",
	0x292: "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested",
	0x294: "AcksTo",
	0x296: "Accept",
	0x298: "CreateSequence",
	0x29A: "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence",
	0x29C: "CreateSequenceRefused",
	0x29E: "CreateSequenceResponse",
	0x2A0: "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse",
	0x2A2: "FaultCode",
	0x2A4: "InvalidAcknowledgement",
	0x2A6: "LastMessage",
	0x2A8: "http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage",
	0x2AA: "LastMessageNumberExceeded",
	0x2AC: "MessageNumberRollover",
	0x2AE: "Nack",
	0x2B0: "netrm",
	0x2B2: "Offer",
	0x2B4: "r",
	0x2B6: "SequenceFault",
	0x2B8: "SequenceTerminated",
	0x2BA: "TerminateSequence",
	0x2BC: "http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence",
	0x2BE: "UnknownSequence",
	0x2C0: "http://schemas.microsoft.com/ws/2006/02/tx/oletx",
	0x2C2: "oletx",
	0x2C4: "OleTxTransaction",
	0x2C6: "PropagationToken",
	0x2C8: "http://schemas.xmlsoap.org/ws/2004/10/wscoor",
	0x2CA: "wscoor",
	0x2CC: "CreateCoordinationContext",
	0x2CE: "CreateCoordinationContextResponse",
	0x2D0: "CoordinationContext",
	0x2D2: "CurrentContext",
	0x2D4: "CoordinationType",
	0x2D6: "RegistrationService",
	0x2D8: "Register",
	0x2DA: "RegisterResponse",
	0x2DC: "ProtocolIdentifier",
	0x2DE: "CoordinatorProtocolService",
	0x2E0: "ParticipantProtocolService",
	0x2E2: "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext",
	0x2E4: "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse",
	0x2E6: "http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register",
	0x2E8: "http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse",
	0x2EA: "http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault",
	0x2EC: "ActivationCoordinatorPortType",
	0x2EE: "RegistrationCoordinatorPortType",
	0x2F0: "InvalidState",
	0x2F2: "InvalidProtocol",
	0x2F4: "InvalidParameters",
	0x2F6: "NoActivity",
	0x2F8: "ContextRefused",
	0x2FA: "AlreadyRegistered",
	0x2FC: "http://schemas.xmlsoap.org/ws/2004/10/wsat",
	0x2FE: "wsat",
	0x300: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion",
	0x302: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC",
	0x304: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC",
	0x306: "Prepare",
	0x308: "Prepared",
	0x30A: "ReadOnly",
	0x30C: "Commit",
	0x30E: "Rollback",
	0x310: "Committed",
	0x312: "Aborted",
	0x314: "Replay",
	0x316: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit",
	0x318: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback",
	0x31A: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed",
	0x31C: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted",
	0x31E: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare",
	0x320: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared",
	0x322: "http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly",
	0x324: "http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay",
	0x326: "http://schemas.xmlsoap.org/ws/2004/10/wsat/fault",
	0x328: "CompletionCoordinatorPortType",
	0x32A: "CompletionParticipantPortType",
	0x32C: "CoordinatorPortType",
	0x32E: "ParticipantPortType",
	0x330: "InconsistentInternalState",
	0x332: "mstx",
	0x334: "Enlistment",
	0x336: "protocol",
	0x338: "LocalTransactionId",
	0x33A: "IsolationLevel",
	0x33C: "IsolationFlags",
	0x33E: "Description",
	0x340: "Loopback",
	0x342: "RegisterInfo",
	0x344: "ContextId",
	0x346: "TokenId",
	0x348: "AccessDenied",
	0x34A: "InvalidPolicy",
	0x34C: "CoordinatorRegistrationFailed",
	0x34E: "TooManyEnlistments",
	0x350: "Disabled",
	0x352: "ActivityId",
	0x354: "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
	0x356: "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1",
	0x358: "http://schemas.xmlsoap.org/ws/2002/12/policy",
	0x35A: "FloodMessage",
	0x35C: "LinkUtility",
	0x35E: "Hops",
	0x360: "http://schemas.microsoft.com/net/2006/05/peer/HopCount",
	0x362: "PeerVia",
	0x364: "http://schemas.microsoft.com/net/2006/05/peer",
	0x366: "PeerFlooder",
	0x368: "PeerTo",
	0x36A: "http://schemas.microsoft.com/ws/2005/05/routing",
	0x36C: "PacketRoutable",
	0x36E: "http://schemas.microsoft.com/ws/2005/05/addressing/none",
	0x370: "http://schemas.microsoft.com/ws/2005/05/envelope/none",
	0x372: "http://www.w3.org/2001/XMLSchema-instance",
	0x374: "http://www.w3.org/2001/XMLSchema",
	0x376: "nil",
	0x378: "type",
	0x37A: "char",
	0x37C: "boolean",
	0x37E: "byte",
	0x380: "unsignedByte",
	0x382: "short",
	0x384: "unsignedShort",
	0x386: "int",
	0x388: "unsignedInt",
	0x38A: "long",
	0x38C: "unsignedLong",
	0x38E: "float",
	0x390: "double",
	0x392: "decimal",
	0x394: "dateTime",
	0x396: "string",
	0x398: "base64Binary",
	0x39A: "anyType",
	0x39C: "duration",
	0x39E: "guid",
	0x3A0: "anyURI",
	0x3A2: "QName",
	0x3A4: "time",
	0x3A6: "date",
	0x3A8: "hexBinary",
	0x3AA: "gYearMonth",
	0x3AC: "gYear",
	0x3AE: "gMonthDay",
	0x3B0: "gDay",
	0x3B2: "gMonth",
	0x3B4: "integer",
	0x3B6: "positiveInteger",
	0x3B8: "negativeInteger",
	0x3BA: "nonPositiveInteger",
	0x3BC: "nonNegativeInteger",
	0x3BE: "normalizedString",
	0x3C0: "ConnectionLimitReached",
	0x3C2: "http://schemas.xmlsoap.org/soap/envelope/",
	0x3C4: "actor",
	0x3C6: "faultcode",
	0x3C8: "faultstring",
	0x3CA: "faultactor",
	0x3CC: "detail",
}

var nbfxInvDict map[string]int

func init() {
	nbfxInvDict = make(map[string]int, len(nbfxDict))
	for k, v := range nbfxDict {
		nbfxInvDict[v] = k
	}
}

func EncodeNBFSE(input string) ([]byte, error) {
	root, err := parseXMLToNBFXTree(input)
	if err != nil {
		return nil, err
	}
	ensureRootNamespaces(root)

	var payload bytes.Buffer
	if err := writeElement(&payload, root, true); err != nil {
		return nil, err
	}

	out := make([]byte, 0, payload.Len()+1)
	out = append(out, 0x00)
	out = append(out, payload.Bytes()...)
	return out, nil
}

func DecodeNBFSE(input []byte) (string, error) {
	if len(input) == 0 {
		return "", fmt.Errorf("empty NBFSE payload")
	}

	off := 0
	// [MC-NBFSE] requires a StringTable prefix. The first field is Size (MultiByteInt31)
	// which indicates the total byte-length of the subsequent String structures.
	stringTableSize, n, err := decodeMBIAt(input, off)
	if err != nil {
		return "", fmt.Errorf("failed to decode StringTable size: %w", err)
	}
	off += n
	if off+int(stringTableSize) > len(input) {
		return "", fmt.Errorf("invalid StringTable size")
	}
	stringTableBytes := input[off : off+int(stringTableSize)]
	off += int(stringTableSize)

	stringTable, err := parseStringTable(stringTableBytes)
	if err != nil {
		return "", err
	}

	root, err := parseNBFXRecords(input[off:], stringTable)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	renderNode(&sb, root)
	return sb.String(), nil
}

func parseStringTable(data []byte) (map[uint32]string, error) {
	// [MC-NBFSE] 2.1: first string has ID=1, each subsequent string increments by 2 (odd IDs).
	// The StringTable Size describes the total size in bytes of the String structures.
	if len(data) == 0 {
		return nil, nil
	}

	result := map[uint32]string{}
	off := 0
	var nextID uint32 = 1

	for off < len(data) {
		s, nOff, err := decodeUTF8StringAt(data, off)
		if err != nil {
			return nil, fmt.Errorf("failed to decode StringTable entry at %d: %w", off, err)
		}
		if _, exists := result[nextID]; exists {
			return nil, fmt.Errorf("duplicate StringTable id %d", nextID)
		}
		result[nextID] = s
		nextID += 2
		off = nOff
	}

	if off != len(data) {
		return nil, fmt.Errorf("StringTable size mismatch: parsed=%d expected=%d", off, len(data))
	}

	return result, nil
}

func parseXMLToNBFXTree(input string) (*nbfxNode, error) {
	dec := xml.NewDecoder(strings.NewReader(input))

	var stack []*nbfxNode
	var root *nbfxNode
	uriToPrefix := map[string]string{}
	nsStack := []map[string]string{copyNSMap(uriToPrefix)}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xml parse error: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			currentNS := copyNSMap(nsStack[len(nsStack)-1])
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" {
					currentNS[a.Value] = a.Name.Local
				} else if a.Name.Space == "" && a.Name.Local == "xmlns" {
					currentNS[a.Value] = ""
				}
			}
			nsStack = append(nsStack, currentNS)

			node := &nbfxNode{Name: t.Name.Local}
			node.Prefix = namespacePrefixFromMap(t.Name.Space, currentNS)
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" {
					node.Attrs = append(node.Attrs, nbfxAttr{Prefix: "xmlns", Name: a.Name.Local, Value: a.Value, IsXMLNS: true})
					continue
				}
				if a.Name.Space == "" && a.Name.Local == "xmlns" {
					node.Attrs = append(node.Attrs, nbfxAttr{Prefix: "", Name: "xmlns", Value: a.Value, IsXMLNS: true})
					continue
				}
				node.Attrs = append(node.Attrs, nbfxAttr{Prefix: namespacePrefixFromMap(a.Name.Space, currentNS), Name: a.Name.Local, Value: a.Value})
			}

			if len(stack) == 0 {
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)

		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if len(nsStack) > 1 {
				nsStack = nsStack[:len(nsStack)-1]
			}

		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			text := string([]byte(t))
			if strings.TrimSpace(text) == "" {
				continue
			}
			stack[len(stack)-1].Text += text
		}
	}

	if root == nil {
		return nil, fmt.Errorf("no root element")
	}

	return root, nil
}

func copyNSMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func ensureRootNamespaces(root *nbfxNode) {
	has := map[string]bool{}
	for _, a := range root.Attrs {
		if a.IsXMLNS {
			if a.Prefix == "xmlns" {
				has[a.Name] = true
			} else if a.Name == "xmlns" {
				has[""] = true
			}
		}
	}

	used := map[string]bool{}
	collectPrefixes(root, used)
	for prefix := range used {
		if prefix == "" {
			continue
		}
		if has[prefix] {
			continue
		}
		for uri, knownPrefix := range knownNSPrefix {
			if knownPrefix == prefix {
				root.Attrs = append(root.Attrs, nbfxAttr{Prefix: "xmlns", Name: prefix, Value: uri, IsXMLNS: true})
				break
			}
		}
	}
}

func collectPrefixes(n *nbfxNode, used map[string]bool) {
	if n.Prefix != "" {
		used[n.Prefix] = true
	}
	for _, a := range n.Attrs {
		if !a.IsXMLNS && a.Prefix != "" {
			used[a.Prefix] = true
		}
	}
	for _, c := range n.Children {
		collectPrefixes(c, used)
	}
}

func writeElement(w *bytes.Buffer, node *nbfxNode, isRoot bool) error {
	if err := writeElementStart(w, node); err != nil {
		return err
	}

	for _, a := range node.Attrs {
		if err := writeAttr(w, a); err != nil {
			return err
		}
	}

	if node.Text != "" {
		if err := writeTextRecord(w, node.Text); err != nil {
			return err
		}
	}

	for _, child := range node.Children {
		if err := writeElement(w, child, false); err != nil {
			return err
		}
	}

	w.WriteByte(0x01)
	_ = isRoot
	return nil
}

func writeElementStart(w *bytes.Buffer, n *nbfxNode) error {
	idx, dict := nbfxInvDict[n.Name]
	switch {
	case dict && len(n.Prefix) == 1:
		t := byte(0x44 + (n.Prefix[0] - 'a'))
		w.WriteByte(t)
		w.Write(encodeMBI(uint32(idx)))
	case dict && n.Prefix != "":
		w.WriteByte(0x43)
		writeUTF8String(w, n.Prefix)
		w.Write(encodeMBI(uint32(idx)))
	case dict:
		w.WriteByte(0x42)
		w.Write(encodeMBI(uint32(idx)))
	case len(n.Prefix) == 1:
		t := byte(0x5E + (n.Prefix[0] - 'a'))
		w.WriteByte(t)
		writeUTF8String(w, n.Name)
	case n.Prefix != "":
		w.WriteByte(0x41)
		writeUTF8String(w, n.Prefix)
		writeUTF8String(w, n.Name)
	default:
		w.WriteByte(0x40)
		writeUTF8String(w, n.Name)
	}
	return nil
}

func writeAttr(w *bytes.Buffer, a nbfxAttr) error {
	if a.IsXMLNS {
		if a.Prefix == "xmlns" {
			if idx, ok := nbfxInvDict[a.Value]; ok {
				w.WriteByte(0x0B)
				writeUTF8String(w, a.Name)
				w.Write(encodeMBI(uint32(idx)))
				return nil
			}
			w.WriteByte(0x09)
			writeUTF8String(w, a.Name)
			writeUTF8String(w, a.Value)
			return nil
		}
		if idx, ok := nbfxInvDict[a.Value]; ok {
			w.WriteByte(0x0A)
			w.Write(encodeMBI(uint32(idx)))
			return nil
		}
		w.WriteByte(0x08)
		writeUTF8String(w, a.Value)
		return nil
	}

	idx, dict := nbfxInvDict[a.Name]
	if len(a.Prefix) == 1 && dict {
		t := byte(0x0C + (a.Prefix[0] - 'a'))
		w.WriteByte(t)
		w.Write(encodeMBI(uint32(idx)))
		return writeTextRecord(w, a.Value)
	}
	if len(a.Prefix) == 1 {
		t := byte(0x26 + (a.Prefix[0] - 'a'))
		w.WriteByte(t)
		writeUTF8String(w, a.Name)
		return writeTextRecord(w, a.Value)
	}
	if dict && a.Prefix != "" {
		w.WriteByte(0x07)
		writeUTF8String(w, a.Prefix)
		w.Write(encodeMBI(uint32(idx)))
		return writeTextRecord(w, a.Value)
	}
	if dict {
		w.WriteByte(0x06)
		w.Write(encodeMBI(uint32(idx)))
		return writeTextRecord(w, a.Value)
	}
	if a.Prefix != "" {
		w.WriteByte(0x05)
		writeUTF8String(w, a.Prefix)
		writeUTF8String(w, a.Name)
		return writeTextRecord(w, a.Value)
	}
	w.WriteByte(0x04)
	writeUTF8String(w, a.Name)
	return writeTextRecord(w, a.Value)
}

func writeTextRecord(w *bytes.Buffer, s string) error {
	if s == "0" {
		w.WriteByte(0x80)
		return nil
	}
	if s == "1" {
		w.WriteByte(0x82)
		return nil
	}
	if strings.EqualFold(s, "false") {
		w.WriteByte(0x84)
		return nil
	}
	if strings.EqualFold(s, "true") {
		w.WriteByte(0x86)
		return nil
	}
	if idx, ok := nbfxInvDict[s]; ok {
		w.WriteByte(0xAA)
		w.Write(encodeMBI(uint32(idx)))
		return nil
	}

	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(s) > 0 {
		if len(b) < 0x100 {
			w.WriteByte(0x9E)
			w.WriteByte(byte(len(b)))
			w.Write(b)
			return nil
		}
		if len(b) < 0x10000 {
			w.WriteByte(0xA0)
			_ = binary.Write(w, binary.LittleEndian, uint16(len(b)))
			w.Write(b)
			return nil
		}
		w.WriteByte(0xA2)
		_ = binary.Write(w, binary.LittleEndian, uint32(len(b)))
		w.Write(b)
		return nil
	}

	utf8 := []byte(s)
	if len(utf8) < 0x100 {
		w.WriteByte(0x98)
		w.WriteByte(byte(len(utf8)))
		w.Write(utf8)
		return nil
	}
	if len(utf8) < 0x10000 {
		w.WriteByte(0x9A)
		_ = binary.Write(w, binary.LittleEndian, uint16(len(utf8)))
		w.Write(utf8)
		return nil
	}
	w.WriteByte(0x9C)
	_ = binary.Write(w, binary.LittleEndian, uint32(len(utf8)))
	w.Write(utf8)
	return nil
}

func parseNBFXRecords(data []byte, stringTable map[uint32]string) (*nbfxNode, error) {
	var root *nbfxNode
	stack := []*nbfxNode{}
	off := 0
	for off < len(data) {
		t := data[off]
		off++

		switch {
		case t == 0x01:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case t >= 0x40 && t <= 0x77:
			n, next, err := decodeElementStart(data, off, t, stringTable)
			if err != nil {
				return nil, err
			}
			off = next
			if len(stack) == 0 {
				root = n
			} else {
				stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, n)
			}
			stack = append(stack, n)

		case t >= 0x04 && t <= 0x3F:
			if len(stack) == 0 {
				return nil, fmt.Errorf("attribute without active element")
			}
			a, next, err := decodeAttr(data, off, t, stringTable)
			if err != nil {
				return nil, err
			}
			off = next
			stack[len(stack)-1].Attrs = append(stack[len(stack)-1].Attrs, a)

		default:
			text, next, ok := decodeText(data, off-1, stringTable)
			if ok {
				off = next
				if len(stack) > 0 {
					stack[len(stack)-1].Text += text
				}
				if _, _, okEnd := decodeTextWithEndType(t); okEnd && len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				continue
			}
			return nil, fmt.Errorf("unsupported NBFX record type 0x%02x", t)
		}
	}

	if root == nil {
		return nil, fmt.Errorf("no NBFX root element")
	}
	return root, nil
}

func decodeElementStart(data []byte, off int, t byte, stringTable map[uint32]string) (*nbfxNode, int, error) {
	n := &nbfxNode{}
	switch {
	case t == 0x40:
		s, nOff, err := decodeUTF8StringAt(data, off)
		if err != nil {
			return nil, off, err
		}
		n.Name = s
		return n, nOff, nil
	case t == 0x41:
		p, nOff, err := decodeUTF8StringAt(data, off)
		if err != nil {
			return nil, off, err
		}
		s, nOff2, err := decodeUTF8StringAt(data, nOff)
		if err != nil {
			return nil, off, err
		}
		n.Prefix, n.Name = p, s
		return n, nOff2, nil
	case t == 0x42:
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return nil, off, err
		}
		n.Name = dictString(idx, stringTable)
		return n, off + nLen, nil
	case t == 0x43:
		p, nOff, err := decodeUTF8StringAt(data, off)
		if err != nil {
			return nil, off, err
		}
		idx, nLen, err := decodeMBIAt(data, nOff)
		if err != nil {
			return nil, off, err
		}
		n.Prefix, n.Name = p, dictString(idx, stringTable)
		return n, nOff + nLen, nil
	case t >= 0x44 && t <= 0x5D:
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return nil, off, err
		}
		n.Prefix = string(rune('a' + int(t-0x44)))
		n.Name = dictString(idx, stringTable)
		return n, off + nLen, nil
	case t >= 0x5E && t <= 0x77:
		s, nOff, err := decodeUTF8StringAt(data, off)
		if err != nil {
			return nil, off, err
		}
		n.Prefix = string(rune('a' + int(t-0x5E)))
		n.Name = s
		return n, nOff, nil
	default:
		return nil, off, fmt.Errorf("invalid element type 0x%02x", t)
	}
}

func decodeAttr(data []byte, off int, t byte, stringTable map[uint32]string) (nbfxAttr, int, error) {
	a := nbfxAttr{}
	var err error
	switch {
	case t == 0x08:
		a.Name = "xmlns"
		a.IsXMLNS = true
		a.Value, off, err = decodeUTF8StringAt(data, off)
		return a, off, err
	case t == 0x09:
		a.IsXMLNS = true
		a.Prefix = "xmlns"
		a.Name, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Value, off, err = decodeUTF8StringAt(data, off)
		return a, off, err
	case t == 0x0A:
		a.IsXMLNS = true
		a.Name = "xmlns"
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Value = dictString(idx, stringTable)
		return a, off + nLen, nil
	case t == 0x0B:
		a.IsXMLNS = true
		a.Prefix = "xmlns"
		a.Name, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Value = dictString(idx, stringTable)
		return a, off + nLen, nil
	case t == 0x04:
		a.Name, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Value, off, err = decodeTextValueOnly(data, off, stringTable)
		return a, off, err
	case t == 0x05:
		a.Prefix, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Name, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Value, off, err = decodeTextValueOnly(data, off, stringTable)
		return a, off, err
	case t == 0x06:
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Name = dictString(idx, stringTable)
		off += nLen
		a.Value, off, err = decodeTextValueOnly(data, off, stringTable)
		return a, off, err
	case t == 0x07:
		a.Prefix, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Name = dictString(idx, stringTable)
		off += nLen
		a.Value, off, err = decodeTextValueOnly(data, off, stringTable)
		return a, off, err
	case t >= 0x0C && t <= 0x25:
		a.Prefix = string(rune('a' + int(t-0x0C)))
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Name = dictString(idx, stringTable)
		off += nLen
		a.Value, off, err = decodeTextValueOnly(data, off, stringTable)
		return a, off, err
	case t >= 0x26 && t <= 0x3F:
		a.Prefix = string(rune('a' + int(t-0x26)))
		a.Name, off, err = decodeUTF8StringAt(data, off)
		if err != nil {
			return a, off, err
		}
		a.Value, off, err = decodeTextValueOnly(data, off, stringTable)
		return a, off, err
	default:
		return a, off, fmt.Errorf("unsupported attribute type 0x%02x", t)
	}
}

func decodeTextValueOnly(data []byte, off int, stringTable map[uint32]string) (string, int, error) {
	if off >= len(data) {
		return "", off, fmt.Errorf("unexpected end while decoding text")
	}
	v, nOff, ok := decodeText(data, off, stringTable)
	if !ok {
		return "", off, fmt.Errorf("unsupported text record type 0x%02x", data[off])
	}
	return v, nOff, nil
}

func decodeTextWithEndType(t byte) (byte, string, bool) {
	base := t - 1
	if _, ok := textTypeName(base); ok {
		return base, "", true
	}
	return 0, "", false
}

func decodeText(data []byte, off int, stringTable map[uint32]string) (string, int, bool) {
	if off >= len(data) {
		return "", off, false
	}
	t := data[off]
	start := off
	off++
	if _, ok := textTypeName(t); !ok {
		if base, _, okEnd := decodeTextWithEndType(t); okEnd {
			t = base
		} else {
			return "", start, false
		}
	}

	switch t {
	case 0x80:
		return "0", off, true
	case 0x82:
		return "1", off, true
	case 0x84:
		return "false", off, true
	case 0x86:
		return "true", off, true
	case 0x88:
		if off+1 > len(data) {
			return "", start, false
		}
		v := int8(data[off])
		off++
		return strconv.FormatInt(int64(v), 10), off, true
	case 0x8A:
		if off+2 > len(data) {
			return "", start, false
		}
		v := int16(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		return strconv.FormatInt(int64(v), 10), off, true
	case 0x8C:
		if off+4 > len(data) {
			return "", start, false
		}
		v := int32(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		return strconv.FormatInt(int64(v), 10), off, true
	case 0x8E:
		if off+8 > len(data) {
			return "", start, false
		}
		v := int64(binary.LittleEndian.Uint64(data[off:]))
		off += 8
		return strconv.FormatInt(v, 10), off, true
	case 0x90:
		if off+4 > len(data) {
			return "", start, false
		}
		bits := binary.LittleEndian.Uint32(data[off:])
		off += 4
		return strconv.FormatFloat(float64(math32frombits(bits)), 'g', -1, 32), off, true
	case 0x92:
		if off+8 > len(data) {
			return "", start, false
		}
		bits := binary.LittleEndian.Uint64(data[off:])
		off += 8
		return strconv.FormatFloat(math64frombits(bits), 'g', -1, 64), off, true
	case 0x98:
		if off+1 > len(data) {
			return "", start, false
		}
		ln := int(data[off])
		off++
		if off+ln > len(data) {
			return "", start, false
		}
		s := string(data[off : off+ln])
		off += ln
		return s, off, true
	case 0x9A:
		if off+2 > len(data) {
			return "", start, false
		}
		ln := int(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		if off+ln > len(data) {
			return "", start, false
		}
		s := string(data[off : off+ln])
		off += ln
		return s, off, true
	case 0x9C:
		if off+4 > len(data) {
			return "", start, false
		}
		ln := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if off+ln > len(data) {
			return "", start, false
		}
		s := string(data[off : off+ln])
		off += ln
		return s, off, true
	case 0x9E:
		if off+1 > len(data) {
			return "", start, false
		}
		ln := int(data[off])
		off++
		if off+ln > len(data) {
			return "", start, false
		}
		b := data[off : off+ln]
		off += ln
		return base64.StdEncoding.EncodeToString(b), off, true
	case 0xA0:
		if off+2 > len(data) {
			return "", start, false
		}
		ln := int(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		if off+ln > len(data) {
			return "", start, false
		}
		b := data[off : off+ln]
		off += ln
		return base64.StdEncoding.EncodeToString(b), off, true
	case 0xA2:
		if off+4 > len(data) {
			return "", start, false
		}
		ln := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if off+ln > len(data) {
			return "", start, false
		}
		b := data[off : off+ln]
		off += ln
		return base64.StdEncoding.EncodeToString(b), off, true
	case 0xA8:
		return "", off, true
	case 0xAA:
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return "", start, false
		}
		off += nLen
		return dictString(idx, stringTable), off, true
	case 0xAC:
		if off+16 > len(data) {
			return "", start, false
		}
		guid := formatGUIDLE(data[off : off+16])
		off += 16
		return "urn:uuid:" + guid, off, true
	case 0xB0:
		if off+16 > len(data) {
			return "", start, false
		}
		guid := formatGUIDLE(data[off : off+16])
		off += 16
		return guid, off, true
	case 0xB2:
		if off+8 > len(data) {
			return "", start, false
		}
		v := binary.LittleEndian.Uint64(data[off:])
		off += 8
		return strconv.FormatUint(v, 10), off, true
	case 0xB4:
		if off+1 > len(data) {
			return "", start, false
		}
		if data[off] == 0 {
			off++
			return "false", off, true
		}
		off++
		return "true", off, true
	case 0xB6:
		if off+1 > len(data) {
			return "", start, false
		}
		ln := int(data[off])
		off++
		if off+ln > len(data) {
			return "", start, false
		}
		s := decodeUTF16LEString(data[off : off+ln])
		off += ln
		return s, off, true
	case 0xB8:
		if off+2 > len(data) {
			return "", start, false
		}
		ln := int(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		if off+ln > len(data) {
			return "", start, false
		}
		s := decodeUTF16LEString(data[off : off+ln])
		off += ln
		return s, off, true
	case 0xBA:
		if off+4 > len(data) {
			return "", start, false
		}
		ln := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if off+ln > len(data) {
			return "", start, false
		}
		s := decodeUTF16LEString(data[off : off+ln])
		off += ln
		return s, off, true
	case 0xBC:
		if off+1 > len(data) {
			return "", start, false
		}
		prefix := string(rune('a' + int(data[off])))
		off++
		idx, nLen, err := decodeMBIAt(data, off)
		if err != nil {
			return "", start, false
		}
		off += nLen
		return prefix + ":" + dictString(idx, stringTable), off, true
	default:
		return "", start, false
	}
}

func dictString(id uint32, stringTable map[uint32]string) string {
	// [MC-NBFS] 2.1: even IDs refer to the static NBFS dictionary.
	// [MC-NBFSE] 2.2: odd IDs refer to entries provided via StringTable.
	if (id & 1) == 1 {
		if stringTable != nil {
			if s, ok := stringTable[id]; ok {
				return s
			}
		}
		return fmt.Sprintf("value_%x", id)
	}
	if s, ok := nbfxDict[int(id)]; ok {
		return s
	}
	return fmt.Sprintf("value_%x", id)
}

func textTypeName(t byte) (string, bool) {
	switch t {
	case 0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x98, 0x9A, 0x9C, 0x9E, 0xA0, 0xA2, 0xA8, 0xAA, 0xAC, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC:
		return "text", true
	default:
		return "", false
	}
}

func renderNode(sb *strings.Builder, n *nbfxNode) {
	sb.WriteByte('<')
	if n.Prefix != "" {
		sb.WriteString(n.Prefix)
		sb.WriteByte(':')
	}
	sb.WriteString(n.Name)
	for _, a := range n.Attrs {
		sb.WriteByte(' ')
		if a.IsXMLNS {
			if a.Prefix == "xmlns" {
				sb.WriteString("xmlns:")
				sb.WriteString(a.Name)
			} else {
				sb.WriteString("xmlns")
			}
		} else {
			if a.Prefix != "" {
				sb.WriteString(a.Prefix)
				sb.WriteByte(':')
			}
			sb.WriteString(a.Name)
		}
		sb.WriteString("=\"")
		sb.WriteString(escapeAttr(a.Value))
		sb.WriteByte('"')
	}
	sb.WriteByte('>')

	if n.Text != "" {
		esc := &bytes.Buffer{}
		_ = xml.EscapeText(esc, []byte(n.Text))
		sb.WriteString(esc.String())
	}
	for _, c := range n.Children {
		renderNode(sb, c)
	}
	sb.WriteString("</")
	if n.Prefix != "" {
		sb.WriteString(n.Prefix)
		sb.WriteByte(':')
	}
	sb.WriteString(n.Name)
	sb.WriteByte('>')
}

func namespacePrefix(uri string) string {
	if uri == "" {
		return ""
	}
	if p, ok := knownNSPrefix[uri]; ok {
		return p
	}
	return "ns"
}

func namespacePrefixFromMap(uri string, uriToPrefix map[string]string) string {
	if uri == "" {
		return ""
	}
	if p, ok := uriToPrefix[uri]; ok {
		return p
	}
	return namespacePrefix(uri)
}

func dictValue(idx int) string {
	if s, ok := nbfxDict[idx]; ok {
		return s
	}
	return fmt.Sprintf("value_%x", idx)
}

func writeUTF8String(w *bytes.Buffer, s string) {
	b := []byte(s)
	w.Write(encodeMBI(uint32(len(b))))
	w.Write(b)
}

func decodeUTF8StringAt(data []byte, off int) (string, int, error) {
	ln, n, err := decodeMBIAt(data, off)
	if err != nil {
		return "", off, err
	}
	off += n
	if off+int(ln) > len(data) {
		return "", off, fmt.Errorf("short utf8 string")
	}
	s := string(data[off : off+int(ln)])
	off += int(ln)
	return s, off, nil
}

func encodeMBI(v uint32) []byte {
	if v <= 0x7F {
		return []byte{byte(v)}
	}
	out := make([]byte, 0, 5)
	for i := 0; i < 5; i++ {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

func decodeMBIAt(data []byte, off int) (uint32, int, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		if off+i >= len(data) {
			return 0, 0, fmt.Errorf("short MBI")
		}
		b := data[off+i]
		v |= uint32(b&0x7F) << (7 * i)
		if (b & 0x80) == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("invalid MBI")
}

func escapeAttr(s string) string {
	rep := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return rep.Replace(s)
}

func formatGUIDLE(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func decodeUTF16LEString(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		runes = append(runes, rune(binary.LittleEndian.Uint16(data[i:i+2])))
	}
	return string(runes)
}

func math32frombits(b uint32) float32 { return math.Float32frombits(b) }
func math64frombits(b uint64) float64 { return math.Float64frombits(b) }
