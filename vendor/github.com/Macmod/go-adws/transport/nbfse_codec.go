package transport

import (
	"bytes"
	"fmt"
	"strings"
)

// NBFSECodec maintains [MC-NBFSE] StringTable mappings across multiple documents.
//
// [MC-NBFSE] 2.1: the first StringTable entry has ID 1, and each subsequent String
// is assigned the next-higher odd number. A consumer MUST maintain this mapping
// until there are no further documents to process.
//
// This codec is used by the transport layer to decode a sequence of SOAP envelopes
// over a single NMF/NNS connection.
type NBFSECodec struct {
	nextOddID   uint32
	stringTable map[uint32]string
}

func NewNBFSECodec() *NBFSECodec {
	return &NBFSECodec{
		nextOddID:   1,
		stringTable: map[uint32]string{},
	}
}

func (c *NBFSECodec) Encode(xml string) ([]byte, error) {
	// Producer-side StringTable optimization is optional. For now we emit an empty
	// StringTable (Size=0) and then the NBFX/NBFS records.
	payload, err := encodeNBFXPayload(xml)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, 1+len(payload))
	out = append(out, 0x00) // StringTable Size = 0 (MultiByteInt31)
	out = append(out, payload...)
	return out, nil
}

func (c *NBFSECodec) Decode(input []byte) (string, error) {
	if len(input) == 0 {
		return "", fmt.Errorf("empty NBFSE payload")
	}

	off := 0
	size, n, err := decodeMBIAt(input, off)
	if err != nil {
		return "", fmt.Errorf("failed to decode StringTable size: %w", err)
	}
	off += n
	if off+int(size) > len(input) {
		return "", fmt.Errorf("invalid StringTable size")
	}

	if size > 0 {
		entries, err := parseStringTableEntries(input[off : off+int(size)])
		if err != nil {
			return "", err
		}
		for _, s := range entries {
			c.stringTable[c.nextOddID] = s
			c.nextOddID += 2
		}
	}
	off += int(size)

	root, err := parseNBFXRecords(input[off:], c.stringTable)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	renderNode(&sb, root)
	return sb.String(), nil
}

// EncodeNBFS encodes XML using NBFX records with the NBFS static dictionary (no StringTable).
// This matches the [MC-NBFS] SOAP Data Structure framing (without [MC-NBFSE] extension).
func EncodeNBFS(input string) ([]byte, error) {
	payload, err := encodeNBFXPayload(input)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeNBFS decodes NBFX/NBFS records to XML (no StringTable prefix).
func DecodeNBFS(input []byte) (string, error) {
	if len(input) == 0 {
		return "", fmt.Errorf("empty NBFS payload")
	}
	root, err := parseNBFXRecords(input, nil)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	renderNode(&sb, root)
	return sb.String(), nil
}

func parseStringTableEntries(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}

	off := 0
	entries := []string{}
	for off < len(data) {
		s, nOff, err := decodeUTF8StringAt(data, off)
		if err != nil {
			return nil, fmt.Errorf("failed to decode StringTable entry at %d: %w", off, err)
		}
		entries = append(entries, s)
		off = nOff
	}
	if off != len(data) {
		return nil, fmt.Errorf("StringTable size mismatch: parsed=%d expected=%d", off, len(data))
	}
	return entries, nil
}

func encodeNBFXPayload(xml string) ([]byte, error) {
	root, err := parseXMLToNBFXTree(xml)
	if err != nil {
		return nil, err
	}
	ensureRootNamespaces(root)

	var payload bytes.Buffer
	if err := writeElement(&payload, root, true); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}
