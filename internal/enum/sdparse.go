package enum

// sdparse.go — Windows Security Descriptor parser for nTSecurityDescriptor.
// Extracts DACL ACEs to determine who has Enroll, AutoEnroll, GenericAll,
// GenericWrite, WriteDACL, WriteOwner on certificate templates and CAs.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Well-known extended right GUIDs for certificate enrollment
const (
	guidEnroll     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	guidAutoEnroll = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
)

// Access mask bits
const (
	accessGenericAll   = 0x10000000
	accessGenericWrite = 0x40000000
	accessWriteDACL    = 0x00040000
	accessWriteOwner   = 0x00080000
	accessExtRight     = 0x00000100 // ADS_RIGHT_DS_CONTROL_ACCESS (extended right)
	accessWriteProp    = 0x00000020 // ADS_RIGHT_DS_WRITE_PROP
)

// ACEInfo represents a parsed Access Control Entry.
type ACEInfo struct {
	SID        string `json:"sid"`
	AccessMask uint32 `json:"access_mask"`
	Type       string `json:"type"` // Allow, Deny
	Rights     string `json:"rights"`
	ObjectGUID string `json:"object_guid,omitempty"` // for object-specific ACEs
}

// SDInfo holds parsed security descriptor data relevant to ADCS.
type SDInfo struct {
	OwnerSID    string    `json:"owner_sid"`
	Enrollers   []ACEInfo `json:"enrollers,omitempty"`
	Writers     []ACEInfo `json:"writers,omitempty"`
	FullControl []ACEInfo `json:"full_control,omitempty"`
}

// ParseSD parses a base64-encoded nTSecurityDescriptor and extracts
// enrollment and write ACEs.
func ParseSD(raw string) *SDInfo {
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(data) < 20 {
		return nil
	}

	info := &SDInfo{}

	// Parse header
	// control := binary.LittleEndian.Uint16(data[2:4])
	ownerOffset := binary.LittleEndian.Uint32(data[4:8])
	// groupOffset := binary.LittleEndian.Uint32(data[8:12])
	// saclOffset := binary.LittleEndian.Uint32(data[12:16])
	daclOffset := binary.LittleEndian.Uint32(data[16:20])

	// Parse owner SID
	if ownerOffset > 0 && int(ownerOffset) < len(data) {
		info.OwnerSID = parseSID(data[ownerOffset:])
	}

	// Parse DACL
	if daclOffset == 0 || int(daclOffset) >= len(data) {
		return info
	}

	dacl := data[daclOffset:]
	if len(dacl) < 8 {
		return info
	}

	// ACL header: revision(1), sbz(1), size(2), aceCount(2), sbz2(2)
	aceCount := int(binary.LittleEndian.Uint16(dacl[4:6]))
	offset := 8 // start of first ACE

	for i := 0; i < aceCount && offset < len(dacl); i++ {
		if offset+4 > len(dacl) {
			break
		}

		aceType := dacl[offset]
		// aceFlags := dacl[offset+1]
		aceSize := int(binary.LittleEndian.Uint16(dacl[offset+2 : offset+4]))

		if aceSize < 4 || offset+aceSize > len(dacl) {
			break
		}

		aceData := dacl[offset : offset+aceSize]

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE
			if len(aceData) >= 8 {
				mask := binary.LittleEndian.Uint32(aceData[4:8])
				sid := parseSID(aceData[8:])
				ace := ACEInfo{SID: sid, AccessMask: mask, Type: "Allow"}
				classifyACE(&ace, "")
				addToSD(info, ace)
			}

		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE
			if len(aceData) >= 12 {
				mask := binary.LittleEndian.Uint32(aceData[4:8])
				flags := binary.LittleEndian.Uint32(aceData[8:12])

				guidOffset := 12
				var objGUID string

				if flags&0x01 != 0 { // ACE_OBJECT_TYPE_PRESENT
					if guidOffset+16 <= len(aceData) {
						objGUID = parseGUID(aceData[guidOffset : guidOffset+16])
						guidOffset += 16
					}
				}
				if flags&0x02 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
					guidOffset += 16 // skip inherited object type
				}

				sid := ""
				if guidOffset < len(aceData) {
					sid = parseSID(aceData[guidOffset:])
				}

				ace := ACEInfo{SID: sid, AccessMask: mask, Type: "Allow", ObjectGUID: objGUID}
				classifyACE(&ace, objGUID)
				addToSD(info, ace)
			}
		}

		offset += aceSize
	}

	return info
}

func classifyACE(ace *ACEInfo, objGUID string) {
	mask := ace.AccessMask
	rights := []string{}

	if mask&accessGenericAll != 0 {
		rights = append(rights, "GenericAll")
	}
	if mask&accessGenericWrite != 0 {
		rights = append(rights, "GenericWrite")
	}
	if mask&accessWriteDACL != 0 {
		rights = append(rights, "WriteDACL")
	}
	if mask&accessWriteOwner != 0 {
		rights = append(rights, "WriteOwner")
	}
	if mask&accessWriteProp != 0 {
		rights = append(rights, "WriteProperty")
	}

	// Extended rights (enrollment)
	if mask&accessExtRight != 0 {
		switch objGUID {
		case guidEnroll:
			rights = append(rights, "Enroll")
		case guidAutoEnroll:
			rights = append(rights, "AutoEnroll")
		case "":
			rights = append(rights, "AllExtendedRights")
		default:
			rights = append(rights, "ExtendedRight")
		}
	}

	if len(rights) == 0 {
		ace.Rights = "Other"
	} else {
		ace.Rights = joinRights(rights)
	}
}

func addToSD(info *SDInfo, ace ACEInfo) {
	mask := ace.AccessMask

	// Full control
	if mask&accessGenericAll != 0 {
		info.FullControl = append(info.FullControl, ace)
		return
	}

	// Enrollment rights
	if mask&accessExtRight != 0 {
		objGUID := ace.ObjectGUID
		if objGUID == guidEnroll || objGUID == guidAutoEnroll || objGUID == "" {
			info.Enrollers = append(info.Enrollers, ace)
			return
		}
	}

	// Write rights (ESC4/ESC7)
	if mask&(accessGenericWrite|accessWriteDACL|accessWriteOwner|accessWriteProp) != 0 {
		info.Writers = append(info.Writers, ace)
		return
	}
}

// parseSID converts binary SID to S-1-5-21-... string format.
func parseSID(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := int(data[1])
	if len(data) < 8+4*subAuthCount {
		return ""
	}

	// Authority is 6 bytes big-endian
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(data[i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount; i++ {
		offset := 8 + 4*i
		subAuth := binary.LittleEndian.Uint32(data[offset : offset+4])
		sid += fmt.Sprintf("-%d", subAuth)
	}
	return sid
}

// parseGUID converts a binary GUID (mixed-endian) to string format.
func parseGUID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	// Windows GUIDs: first 3 components little-endian, last 2 big-endian
	d1 := binary.LittleEndian.Uint32(data[0:4])
	d2 := binary.LittleEndian.Uint16(data[4:6])
	d3 := binary.LittleEndian.Uint16(data[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])
}

func joinRights(rights []string) string {
	result := ""
	for i, r := range rights {
		if i > 0 {
			result += ", "
		}
		result += r
	}
	return result
}

// Well-known SIDs for display
var wellKnownSIDs = map[string]string{
	"S-1-0-0":       "Nobody",
	"S-1-1-0":       "Everyone",
	"S-1-5-7":       "Anonymous",
	"S-1-5-11":      "Authenticated Users",
	"S-1-5-18":      "SYSTEM",
	"S-1-5-32-544":  "Administrators",
	"S-1-5-32-545":  "Users",
	"S-1-5-32-546":  "Guests",
}

// FriendlySID returns a human-readable name for well-known SIDs,
// or the raw SID for domain-specific ones.
func FriendlySID(sid, domainSID string) string {
	if name, ok := wellKnownSIDs[sid]; ok {
		return name
	}
	// Domain-specific well-known RIDs
	if domainSID != "" && len(sid) > len(domainSID)+1 {
		prefix := sid[:len(domainSID)]
		if prefix == domainSID {
			rid := sid[len(domainSID)+1:]
			switch rid {
			case "513":
				return "Domain Users"
			case "512":
				return "Domain Admins"
			case "515":
				return "Domain Computers"
			case "516":
				return "Domain Controllers"
			case "519":
				return "Enterprise Admins"
			case "498":
				return "Enterprise Read-Only DCs"
			case "517":
				return "Cert Publishers"
			}
		}
	}
	return sid
}
