// Package transport is declared here for nmf.go; see nns.go for the package-level doc comment.
package transport

import (
	"fmt"
	"io"
	"net"
)

// NMFConnection represents a .NET Message Framing protocol connection.
//
// NMF provides message boundaries and encoding negotiation on top of NNS.
//
// References:
//   - [MC-NMF]: .NET Message Framing Protocol
//   - Used by WCF (Windows Communication Foundation)
type NMFConnection struct {
	transport *NNSConnection // Underlying NNS connection
	rawConn   net.Conn       // Raw TCP connection (for pre-auth handshake)
	fqdn      string         // DC FQDN for addressing
	port      int            // ADWS port for Via URI
	mode      uint8          // Connection mode (Duplex/Simplex/etc)
	encoding  uint8          // SOAP encoding (SOAP1_2_BINARY_INBAND_DICT)
	codec     *NBFSECodec    // Stateful NBFSE codec for BinaryDict
	noAuth    bool           // True for unauthenticated endpoints (e.g. mex)
}

// Connection modes (from [MC-NMF] 2.2.3.1.2)
const (
	ModeSingleton     uint8 = 0x01
	ModeDuplex        uint8 = 0x02 // Most common for ADWS
	ModeSimplex       uint8 = 0x03
	ModeDuplexSession uint8 = 0x04
)

// Known encodings (from [MC-NMF] 2.2.3.4.1)
const (
	// SOAP 1.1 encodings
	EncodingSOAP11UTF8    uint8 = 0x00
	EncodingSOAP11UTF16   uint8 = 0x01
	EncodingSOAP11UTF16LE uint8 = 0x02

	// SOAP 1.2 encodings; ADWS requires EncodingSOAP12BinaryDict (0x08)
	EncodingSOAP12UTF8       uint8 = 0x03
	EncodingSOAP12UTF16      uint8 = 0x04
	EncodingSOAP12UTF16LE    uint8 = 0x05
	EncodingSOAP12MTOM       uint8 = 0x06
	EncodingSOAP12Binary     uint8 = 0x07 // Binary XML (NBFS)
	EncodingSOAP12BinaryDict uint8 = 0x08 // Most efficient - used by ADWS
)

// NMF Record Types (from [MC-NMF] 2.2.1 Record Types table)
const (
	RecordTypeVersion     uint8 = 0x00 // Version Record
	RecordTypeMode        uint8 = 0x01 // Mode Record
	RecordTypeVia         uint8 = 0x02 // Via Record
	RecordTypeEncoding    uint8 = 0x03 // Known Encoding Record
	RecordTypeExtEncoding uint8 = 0x04 // Extensible Encoding Record
	RecordTypeUnsizedEnv  uint8 = 0x05 // Unsized Envelope Record
	RecordTypeSizedEnv    uint8 = 0x06 // Sized Envelope Record
	RecordTypeEnd         uint8 = 0x07 // End Record
	RecordTypeFault       uint8 = 0x08 // Fault Record
	RecordTypeUpgradeReq  uint8 = 0x09 // Upgrade Request Record
	RecordTypeUpgradeRes  uint8 = 0x0A // Upgrade Response Record
	RecordTypePreambleAck uint8 = 0x0B // Preamble Ack Record (was incorrectly 0x01)
	RecordTypePreambleEnd uint8 = 0x0C // Preamble End Record (was incorrectly 0x02)
)

// NewNMFConnection creates an NMF connection over the given NNS transport.
// Authentication is performed later when Connect is called.
func NewNMFConnection(transport *NNSConnection, fqdn string, port int) *NMFConnection {
	if port == 0 {
		port = 9389
	}

	nmf := &NMFConnection{
		transport: transport,
		rawConn:   transport.conn, // Store raw conn for pre-auth handshake
		fqdn:      fqdn,
		port:      port,
		mode:      ModeDuplex,               // ADWS uses duplex mode
		encoding:  EncodingSOAP12BinaryDict, // ADWS expected encoding for this implementation
	}
	if nmf.encoding == EncodingSOAP12BinaryDict {
		nmf.codec = NewNBFSECodec()
	}
	return nmf
}

// Connect establishes the NMF connection to the specified ADWS resource endpoint.
//
// Connection sequence (per MC-NMF spec):
//   1. Send NMF Preamble on raw TCP (pre-auth)
//   2. Send Upgrade Request on raw TCP (pre-auth)
//   3. Receive Upgrade Response on raw TCP (pre-auth)
//   4. Perform NNS authentication handshake on raw TCP (handshake messages unprotected per MS-NNS 2.2.1)
//   5. Send Preamble End via NNS transport (post-auth, protected)
//   6. Receive Preamble Ack via NNS transport (post-auth, protected)
//
// Endpoints:
//   - Windows/Enumeration    - LDAP queries (Enumerate/Pull)
//   - Windows/Resource       - Get/Put operations
//   - Windows/ResourceFactory - Create objects
//   - Windows/AccountManagement - Account operations
//   - Windows/TopologyManagement - DC operations
func (nmf *NMFConnection) Connect(resource string) error {
	// Step 1: Send Preamble record on raw TCP (before auth)
	if err := nmf.sendPreamble(resource); err != nil {
		return fmt.Errorf("failed to send preamble: %w", err)
	}

	// The "mex" endpoint neither requires nor supports NNS authentication (MS-ADDM §2.1).
	// Skip the upgrade handshake entirely for anonymous/no-protection connections.
	if nmf.transport.credentialType == CredentialAnonymous && nmf.transport.protectionLevel == ProtectionNone {
		nmf.noAuth = true
	} else {
		// Step 2: Send Upgrade Request on raw TCP (before auth)
		if err := nmf.sendUpgradeRequest(); err != nil {
			return fmt.Errorf("failed to send upgrade request: %w", err)
		}

		// Step 3: Receive Upgrade Response on raw TCP (before auth)
		if err := nmf.recvUpgradeResponse(); err != nil {
			return fmt.Errorf("failed to receive upgrade response: %w", err)
		}

		// Step 4: Perform NNS authentication handshake on raw TCP.
		if err := nmf.transport.Authenticate(); err != nil {
			return fmt.Errorf("NNS authentication failed: %w", err)
		}
	}

	// Step 5: Send Preamble End.
	endRecord := []byte{RecordTypePreambleEnd}
	if nmf.noAuth {
		if _, err := nmf.rawConn.Write(endRecord); err != nil {
			return fmt.Errorf("failed to send preamble end: %w", err)
		}
	} else {
		if err := nmf.transport.Send(endRecord); err != nil {
			return fmt.Errorf("failed to send preamble end: %w", err)
		}
	}

	// Step 6: Receive Preamble Ack.
	if err := nmf.recvPreambleAck(); err != nil {
		return fmt.Errorf("failed to receive preamble ack: %w", err)
	}

	// Connection established and ready for SOAP message exchange
	return nil
}

// Send sends a SOAP message encapsulated in an NMF SizedEnvelope record.
//
// SizedEnvelope format:
//   [0]     RecordType (0x06)
//   [1:.]   EncodedSize (variable-length integer)
//   [...]   SOAP payload (binary XML when using SOAP12Binary/Dict)
func (nmf *NMFConnection) Send(soapMessage string) error {
	payload := []byte(soapMessage)
	if nmf.encoding == EncodingSOAP12Binary {
		encoded, err := EncodeNBFS(soapMessage)
		if err != nil {
			return fmt.Errorf("failed to encode NBFS payload: %w", err)
		}
		payload = encoded
	}
	if nmf.encoding == EncodingSOAP12BinaryDict {
		codec := nmf.codec
		if codec == nil {
			codec = NewNBFSECodec()
		}
		encoded, err := codec.Encode(soapMessage)
		if err != nil {
			return fmt.Errorf("failed to encode NBFSE payload: %w", err)
		}
		payload = encoded
	}

	// Build SizedEnvelope record: [RecordType][EncodedSize][Payload]
	sizeEnc := encodeRecordSize(uint32(len(payload)))
	record := make([]byte, 1+len(sizeEnc)+len(payload))
	record[0] = RecordTypeSizedEnv
	copy(record[1:], sizeEnc)
	copy(record[1+len(sizeEnc):], payload)

	if nmf.noAuth {
		_, err := nmf.rawConn.Write(record)
		return err
	}

	if err := nmf.transport.Send(record); err != nil {
		return fmt.Errorf("failed to send NMF record: %w", err)
	}

	return nil
}

// Recv receives a SOAP message from an NMF SizedEnvelope record.
func (nmf *NMFConnection) Recv() (string, error) {
	// NNS delivers one protected frame; parse NMF record(s) from it.
	buf := make([]byte, 1024*1024)
	var n int
	var err error
	if nmf.noAuth {
		n, err = nmf.rawConn.Read(buf)
	} else {
		n, err = nmf.transport.Recv(buf)
	}
	if err != nil {
		return "", fmt.Errorf("failed to read NMF frame: %w", err)
	}
	if n < 1 {
		return "", fmt.Errorf("empty NMF frame")
	}
	frame := buf[:n]

	switch frame[0] {
	case RecordTypeSizedEnv:
		size, sizeLen, err := decodeRecordSize(frame[1:])
		if err != nil {
			return "", fmt.Errorf("failed to decode sized envelope length: %w", err)
		}
		start := 1 + sizeLen
		if start > len(frame) {
			return "", fmt.Errorf("invalid sized envelope header: start=%d frame=%d", start, len(frame))
		}

		totalPayload := int(size)
		payload := make([]byte, 0, totalPayload)
		payload = append(payload, frame[start:]...)

		for len(payload) < totalPayload {
			if nmf.noAuth {
				n, err = nmf.rawConn.Read(buf)
			} else {
				n, err = nmf.transport.Recv(buf)
			}
			if err != nil {
				return "", fmt.Errorf("failed to read NMF continuation frame: %w", err)
			}
			if n == 0 {
				return "", fmt.Errorf("unexpected empty continuation frame")
			}
			payload = append(payload, buf[:n]...)
		}

		if len(payload) > totalPayload {
			payload = payload[:totalPayload]
		}

		if nmf.encoding == EncodingSOAP12Binary || nmf.encoding == EncodingSOAP12BinaryDict {
			if nmf.encoding == EncodingSOAP12Binary {
				decoded, err := DecodeNBFS(payload)
				if err != nil {
					return "", fmt.Errorf("failed to decode NBFS payload: %w", err)
				}
				return decoded, nil
			}
			codec := nmf.codec
			if codec == nil {
				codec = NewNBFSECodec()
				nmf.codec = codec
			}
			decoded, err := codec.Decode(payload)
			if err != nil {
				return "", fmt.Errorf("failed to decode NBFSE payload: %w", err)
			}
			return decoded, nil
		}

		return string(payload), nil

	case RecordTypeFault:
		faultSize, sizeLen, err := decodeRecordSize(frame[1:])
		if err != nil {
			return "", fmt.Errorf("failed to decode fault size: %w", err)
		}
		start := 1 + sizeLen
		end := start + int(faultSize)
		if end > len(frame) {
			return "", fmt.Errorf("fault record truncated")
		}
		return "", fmt.Errorf("server returned fault record: %s", string(frame[start:end]))

	case RecordTypeEnd:
		// Connection closed by server
		return "", io.EOF

	default:
		return "", fmt.Errorf("unexpected record type: 0x%02x", frame[0])
	}
}

// sendPreamble sends the NMF preamble record.
func (nmf *NMFConnection) sendPreamble(resource string) error {
	// Build Via URL: net.tcp://fqdn:port/ActiveDirectoryWebServices/{resource}
	via := fmt.Sprintf("net.tcp://%s:%d/ActiveDirectoryWebServices/%s", nmf.fqdn, nmf.port, resource)

	// The Preamble consists of separate records:
	//   1. Version Record (RecordType=0x00)
	//   2. Mode Record (RecordType=0x01)
	//   3. Via Record (RecordType=0x03)
	//   4. Known Encoding Record (RecordType=0x04)

	// 1. Version Record: [RecordType][MajorVersion][MinorVersion]
	versionRec := []byte{
		RecordTypeVersion, // RecordType = Version Record (0x00)
		0x01,              // VersionMajor = 1
		0x00,              // VersionMinor = 0
	}
	if _, err := nmf.rawConn.Write(versionRec); err != nil {
		return fmt.Errorf("failed to write version record: %w", err)
	}

	// 2. Mode Record: [RecordType][Mode]
	modeRec := []byte{
		RecordTypeMode, // RecordType = Mode Record (0x01)
		nmf.mode,       // Mode (0x02 = Duplex)
	}
	if _, err := nmf.rawConn.Write(modeRec); err != nil {
		return fmt.Errorf("failed to write mode record: %w", err)
	}

	// 3. Via Record: [RecordType][Length][Via URL]
	viaBytes := []byte(via)
	viaLen := len(viaBytes)

	viaRec := make([]byte, 0, 2+viaLen)
	viaRec = append(viaRec, RecordTypeVia) // RecordType = Via Record (0x02)

	// Encode length
	if viaLen < 0x80 {
		viaRec = append(viaRec, byte(viaLen))
	} else if viaLen < 0x4000 {
		viaRec = append(viaRec, byte(0x80|(viaLen>>8)), byte(viaLen&0xff))
	} else {
		return fmt.Errorf("via URL too long: %d bytes", viaLen)
	}
	viaRec = append(viaRec, viaBytes...)

	if _, err := nmf.rawConn.Write(viaRec); err != nil {
		return fmt.Errorf("failed to write via record: %w", err)
	}

	// 4. Known Encoding Record: [RecordType][Encoding]
	encodingRec := []byte{
		RecordTypeEncoding, // RecordType = Known Encoding Record (0x03)
		nmf.encoding,
	}
	if _, err := nmf.rawConn.Write(encodingRec); err != nil {
		return fmt.Errorf("failed to write encoding record: %w", err)
	}
	return nil
}

// recvPreambleAck receives and validates the PreambleAck record.
func (nmf *NMFConnection) recvPreambleAck() error {
	recordType := make([]byte, 1)
	if nmf.noAuth {
		if _, err := io.ReadFull(nmf.rawConn, recordType); err != nil {
			return fmt.Errorf("failed to read preamble ack: %w", err)
		}
	} else {
		// Read record type byte from NNS (after authentication, wrapped)
		n, err := nmf.transport.Recv(recordType)
		if err != nil {
			return fmt.Errorf("failed to read preamble ack: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("failed to read preamble ack")
		}
	}

	// Validate record type
	if recordType[0] != RecordTypePreambleAck {
		return fmt.Errorf("expected PreambleAck (0x0B), got 0x%02x", recordType[0])
	}

	return nil
}

// sendUpgradeRequest sends an upgrade request for NNS protocol.
func (nmf *NMFConnection) sendUpgradeRequest() error {
	// Format:
	//   [0]   RecordType (0x09)
	//   [1:] Protocol string "application/negotiate" (length-prefixed)

	protocol := "application/negotiate"
	protocolBytes := []byte(protocol)
	length := len(protocolBytes)

	// Build upgrade request
	upgradeReq := make([]byte, 0, 2+length)
	upgradeReq = append(upgradeReq, RecordTypeUpgradeReq) // [0] RecordType

	// Encode protocol string (length-prefixed)
	if length < 0x80 {
		upgradeReq = append(upgradeReq, byte(length))
	} else if length < 0x4000 {
		upgradeReq = append(upgradeReq, byte(0x80|(length>>8)), byte(length&0xff))
	} else {
		return fmt.Errorf("protocol string too long: %d bytes", length)
	}
	upgradeReq = append(upgradeReq, protocolBytes...)

	// Send on raw connection (before authentication)
	_, err := nmf.rawConn.Write(upgradeReq)
	return err
}

// recvUpgradeResponse receives and validates the upgrade response.
func (nmf *NMFConnection) recvUpgradeResponse() error {
	// Read record type byte from raw connection (before authentication)
	recordType := make([]byte, 1)
	if _, err := io.ReadFull(nmf.rawConn, recordType); err != nil {
		return fmt.Errorf("failed to read upgrade response: %w", err)
	}

	if recordType[0] == RecordTypeFault {
		faultSize, err := readRecordSize(nmf.rawConn)
		if err != nil {
			return fmt.Errorf("received fault record but failed to read fault size: %w", err)
		}

		faultPayload := make([]byte, faultSize)
		if _, err := io.ReadFull(nmf.rawConn, faultPayload); err != nil {
			return fmt.Errorf("received fault record but failed to read fault payload: %w", err)
		}

		return fmt.Errorf("server returned fault record during upgrade: %s", string(faultPayload))
	}

	// Validate record type
	if recordType[0] != RecordTypeUpgradeRes {
		return fmt.Errorf("expected UpgradeResponse (0x0a), got 0x%02x", recordType[0])
	}

	// Per [MC-NMF] 3.1.4.8: "If the upgrade is supported, the participant MUST invoke the
	// appropriate upgrade handler. How the upgrade handler achieves the upgrade is outside
	// the scope of this document."
	//
	// For "application/negotiate" upgrades, the upgrade handler is the NNS authentication layer.
	// The NNS layer is responsible for handling the GSS-API/SPNEGO handshake that follows.
	// The NMF layer does not read those protocol exchange bytes - they are handled by NNS.

	return nil
}

func encodeRecordSize(size uint32) []byte {
	if size <= 0x7F {
		return []byte{byte(size)}
	}

	encoded := make([]byte, 0, 5)
	for {
		b := byte(size & 0x7F)
		size >>= 7
		if size > 0 {
			b |= 0x80
		}
		encoded = append(encoded, b)
		if size == 0 {
			break
		}
	}
	return encoded
}

func decodeRecordSize(data []byte) (uint32, int, error) {
	var (
		size  uint32
		shift uint
	)

	for i := 0; i < len(data) && i < 5; i++ {
		b := data[i]
		size |= uint32(b&0x7F) << shift
		if (b & 0x80) == 0 {
			if size == 0 {
				return 0, 0, fmt.Errorf("invalid zero size")
			}
			return size, i + 1, nil
		}
		shift += 7
	}

	if len(data) < 5 {
		return 0, 0, fmt.Errorf("incomplete encoded size")
	}
	return 0, 0, fmt.Errorf("invalid encoded size")
}

func readRecordSize(r io.Reader) (uint32, error) {
	var (
		size  uint32
		shift uint
	)

	for i := 0; i < 5; i++ {
		b := make([]byte, 1)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}

		size |= uint32(b[0]&0x7F) << shift
		if (b[0] & 0x80) == 0 {
			if size == 0 {
				return 0, fmt.Errorf("invalid zero size")
			}
			return size, nil
		}

		shift += 7
	}

	return 0, fmt.Errorf("invalid encoded size")
}
