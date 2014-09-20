package keyless

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// From kssl.h

type Packet struct {
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
	OpRSASignSHA1    = 0x03
	OpRSASignSHA224  = 0x04
	OpRSASignSHA256  = 0x05
	OpRSASignSHA384  = 0x06
	OpRSASignSHA512  = 0x07

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

type Conn struct {
	mu   sync.Mutex
	conn net.Conn

	id uint32
}

func Dial(remote string, config *tls.Config) (*Conn, error) {

	var c Conn

	var err error
	c.conn, err = tls.Dial("tcp", remote, config)

	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *Conn) Ping(payload []byte) ([]Item, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	var p Packet

	p.VersionMaj = VersionMaj
	p.ID = c.id
	c.id++

	p.Items = []Item{
		{Tag: TagOPCODE, Data: []byte{OpPing}},
		{Tag: TagPayload, Data: payload},
	}

	b, _ := Marshal(p)

	_, err := c.conn.Write(b)
	if err != nil {
		return nil, err
	}

	var header [8]byte

	c.conn.Read(header[:])

	rlen := binary.BigEndian.Uint16(header[2:])

	response := make([]byte, (rlen + 8))
	copy(response, header[:])

	c.conn.Read(response[8:])

	var r Packet
	Unmarshal(response[:], &r)

	if r.ID != p.ID {
		return nil, errors.New("out of sequence response")
	}

	return r.Items, nil
}

func Marshal(p Packet) ([]byte, error) {

	var b []byte

	b = append(b, p.VersionMaj, p.VersionMin)
	b = append16(b, 0)
	b = append32(b, p.ID)

	for _, item := range p.Items {
		b = appendItem(b, item)
	}

	// pad response to at least padTo length
	var padding []byte
	if len(b) < padTo {
		padding = make([]byte, padTo-len(b))
	}
	b = appendItem(b, Item{Tag: TagPadding, Data: padding})

	binary.BigEndian.PutUint16(b[2:], uint16(len(b)-headerSize))

	return b, nil
}

func Unmarshal(b []byte, p *Packet) error {

	blen := len(b)

	p.VersionMaj, p.VersionMin = b[0], b[1]
	b = b[2:]

	length := binary.BigEndian.Uint16(b[:])
	b = b[2:]

	if int(length)+headerSize != blen {
		return errors.New("short packet")
	}

	p.ID = binary.BigEndian.Uint32(b[:])
	b = b[4:]

	for len(b) > 0 {
		var item Item
		var err error
		b, err = readItem(b, &item)
		if err != nil {
			return err
		}
		p.Items = append(p.Items, item)
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

	item.Data, b = b[:l], b[l:]

	return b, nil
}
