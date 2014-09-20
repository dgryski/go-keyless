package keyless

import (
	"encoding/binary"
	"log"
)

// From kssl.h

type Header struct {
	VersionMaj byte
	VersionMin byte
	ID         uint32
	Items      []Item
}

const headerSize = 8

// The current KSSL protocol version
const (
	VersionMaj byte = 0x01
	VersionMin      = 0x00
)

type Tag byte

// Possible item tags
const (
	TagDigest   Tag = 0x01 // An RSA key digest (see digest_public_modulus)
	TagSNI          = 0x02 // Server name (optional)
	TagClientIP     = 0x03 // Client IP (4 bytes for IPv4, 16 for IPv6)
	TagOPCODE       = 0x11 // Requested operation (one of KSSL_OP_*)
	TagPayload      = 0x12 // Payload
	TagPadding      = 0x20 // Padding
)

// This structure stores the value of a given tag
type Item struct {
	Tag  Tag    // Tag to identify contents of item
	Data []byte // The block of data to decrypt or sign
}

// Number of bytes to pad responses to
const padTo = 1024

// A test message which will be echoed with its payload with the
// operation changed to OP_PONG

// Possible values for KSSL_TAG_OPCODE
const (
	OpPing byte = 0xF1
	OpPong      = 0xF2

	// Decrypt data encrypted using RSA with RSA_PKCS1_PADDING
	OpRSADecrypt = 0x01

	// Sign data using RSA
	OpRSASignMD5SHA1 = 0x02
	OPRSASignSHA1    = 0x03
	OPRSASignSHA224  = 0x04
	OPRSASignSHA256  = 0x05
	OPRSASignSHA384  = 0x06
	OPRSASignSHA512  = 0x07

	// Used to send a block of data back to the client (in response, for
	// example, to a KSSL_OP_RSA_DECRYPT)
	OpResponse = 0xF0

	// Some error occurred, explanation is single byte in payload
	OpError = 0xFF
)

type ErrCode byte

// Different error codes for OpError payload
const (
	ErrNone             ErrCode = 0x00
	ErrCryptoFailed             = 0x01
	ErrKeyNotFound              = 0x02
	ErrRead                     = 0x03
	ErrVersionMismatch          = 0x04
	ErrBadOpcode                = 0x05
	ErrUnexpectedOpcode         = 0x06
	ErrFormat                   = 0x07
	ErrInternal                 = 0x08
)

func Marshal(h Header) ([]byte, error) {

	var b []byte

	b = append(b, h.VersionMaj, h.VersionMin)
	// TODO(dgryski): backpatch real length later
	b = append16(b, padTo-headerSize)
	b = append32(b, h.ID)

	for _, item := range h.Items {
		b = appendItem(b, item)
	}

	// pad response to padTo length.. wow, this is ugly
	b = appendItem(b, Item{Tag: TagPadding, Data: make([]byte, padTo-len(b)-3)})

	return b, nil
}

func Unmarshal(b []byte, h *Header) error {

	blen := len(b)

	h.VersionMaj, h.VersionMin = b[0], b[1]
	b = b[2:]

	length := binary.BigEndian.Uint16(b[:])
	b = b[2:]
	if false {
		// FIXME(dgryski): verify provided length and len(b) match up
		log.Printf("length %d, blen %d\n", length, blen)
	}

	h.ID = binary.BigEndian.Uint32(b[:])
	b = b[4:]

	for len(b) > 0 {
		var item Item
		var err error
		b, err = readItem(b, &item)
		if err != nil {
			return err
		}
		h.Items = append(h.Items, item)
	}

	return nil
}

func append16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func append32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendItem(b []byte, item Item) []byte {

	b = append(b, byte(item.Tag))
	b = append16(b, uint16(len(item.Data)))
	b = append(b, item.Data...)

	return b
}

func readItem(b []byte, item *Item) ([]byte, error) {

	item.Tag = Tag(b[0])
	b = b[1:]

	l := binary.BigEndian.Uint16(b[:])
	b = b[2:]

	if item.Tag == TagPadding {
		// Bug in kssl_helpers.c:flatten_operation() ?
		l -= 3
	}

	item.Data, b = b[:l], b[l:]

	return b, nil
}
