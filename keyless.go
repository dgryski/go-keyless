package keyless

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

func (e ErrCode) Error() string {

	switch e {
	case 0x00:
		return "success"
	case 0x01:
		return "cryptography failure"
	case 0x02:
		return "key not found"
	case 0x03:
		return "read error"
	case 0x04:
		return "version mismatch"
	case 0x05:
		return "bad opcode"
	case 0x06:
		return "unexpected opcode"
	case 0x07:
		return "format error"
	case 0x08:
		return "internal error"
	}

	return "unknown"
}

type Conn struct {
	conn net.Conn

	mu      sync.Mutex
	pending map[uint32]chan []byte

	// data to be written to the socket
	write chan []byte

	// these are signals *from* the reader and writer routines that they're not going to process anymore
	doneRead  chan bool
	doneWrite chan bool

	// we have been asked to close
	done chan bool

	id uint32
}

func Dial(remote string, config *tls.Config) (*Conn, error) {

	var c Conn

	var err error
	c.conn, err = tls.Dial("tcp", remote, config)

	if err != nil {
		return nil, err
	}

	c.done = make(chan bool)
	c.doneRead = make(chan bool)
	c.doneWrite = make(chan bool)

	c.pending = make(map[uint32]chan []byte)
	c.write = make(chan []byte)

	go c.reader()
	go c.writer()

	return &c, nil
}

func (c *Conn) Close() {
	select {
	case <-c.done:
		// done channel already closed? Nothing to do
		return
	default:
		// signal cleanup
		close(c.done)
		c.conn.Close()
	}
}

func (c *Conn) writer() {

FOR:
	for {
		select {
		case <-c.done:
			break FOR
		case b := <-c.write:
			_, err := c.conn.Write(b)
			if err != nil {
				break FOR
			}
		}
	}

	close(c.doneWrite)
}

func (c *Conn) reader() {

FOR:
	for {
		select {
		case <-c.done:
			break FOR
		default:
		}

		var header [8]byte

		// FIXME(dgryski): need another timeout on these reads
		_, err := io.ReadFull(c.conn, header[:])
		if err != nil {
			// partial read -- unknown connection state
			break
		}

		rlen := binary.BigEndian.Uint16(header[2:])
		id := binary.BigEndian.Uint32(header[4:])

		response := make([]byte, rlen+8)
		copy(response, header[:])

		_, err = io.ReadFull(c.conn, response[8:])
		if err != nil {
			// partial read -- unknown connection state
			break
		}

		c.mu.Lock()
		ch := c.pending[id]
		if ch != nil {
			delete(c.pending, id)
		}
		c.mu.Unlock()

		if ch != nil {
			ch <- response
		} else {
			// message for unknown id
		}
	}

	// tell everybody waiting for a request that the reader isn't processing any more
	close(c.doneRead)
}

var ErrBadResponse = errors.New("bad response packet")

func (c *Conn) Ping(payload []byte) ([]byte, error) {

	items := []Item{
		{Tag: TagOPCODE, Data: []byte{OpPing}},
		{Tag: TagPayload, Data: payload},
	}

	response, err := c.doRequest(items)

	if err != nil {
		return nil, err
	}

	// probably shouldn't depend on the order of response packets..
	if len(response) != 2 ||
		response[0].Tag != TagOPCODE ||
		len(response[0].Data) != 1 ||
		response[0].Data[0] != OpPong ||
		response[1].Tag != TagPayload {
		return nil, ErrBadResponse
	}

	return response[1].Data, nil
}

func (c *Conn) Decrypt(digest, payload []byte) ([]byte, error) {

	items := []Item{
		{Tag: TagOPCODE, Data: []byte{OpRSADecrypt}},
		{Tag: TagPayload, Data: payload},
		{Tag: TagDigest, Data: digest},
	}

	response, err := c.doRequest(items)
	if err != nil {
		return nil, err
	}

	// probably shouldn't depend on the order of response packets..
	if len(response) != 2 ||
		response[0].Tag != TagOPCODE ||
		len(response[0].Data) != 1 ||
		response[1].Tag != TagPayload {
		return nil, ErrBadResponse
	}

	if response[0].Data[0] == OpError {
		return nil, ErrCode(response[1].Data[0])
	}

	return response[1].Data, nil
}

func (c *Conn) Sign(digest []byte, op byte, payload []byte) ([]byte, error) {

	items := []Item{
		{Tag: TagOPCODE, Data: []byte{op}},
		{Tag: TagPayload, Data: payload},
		{Tag: TagDigest, Data: digest},
	}

	response, err := c.doRequest(items)
	if err != nil {
		return nil, err
	}

	// probably shouldn't depend on the order of response packets..
	if len(response) != 2 ||
		response[0].Tag != TagOPCODE ||
		len(response[0].Data) != 1 ||
		response[1].Tag != TagPayload {
		return nil, ErrBadResponse
	}

	if response[0].Data[0] == OpError {
		return nil, ErrCode(response[1].Data[0])
	}

	return response[1].Data, nil
}

func (c *Conn) doRequest(items []Item) ([]Item, error) {

	select {
	case <-c.done:
		return nil, io.EOF
	default:

	}

	id := atomic.AddUint32(&c.id, 1)

	p := Packet{
		VersionMaj: VersionMaj,
		ID:         id,
		Items:      items,
	}

	b, _ := Marshal(p)

	ch := make(chan []byte, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()

	select {
	case <-c.doneWrite:
		return nil, io.EOF
	case c.write <- b:
	}

	select {
	case <-c.doneRead:
		return nil, io.EOF
	case b = <-ch:
	}

	var r Packet
	Unmarshal(b, &r)

	// docs say response is two items, plus padding.
	// strip out the padding, complain if it's not there.
	if len(r.Items) != 3 || r.Items[len(r.Items)-1].Tag != TagPadding {
		return nil, ErrBadResponse
	}

	return r.Items[:len(r.Items)-1], nil
}

func DigestPublicModulus(pub *rsa.PublicKey) [32]byte {
	dst := make([]byte, hex.EncodedLen(len(pub.N.Bytes())))
	hex.Encode(dst, pub.N.Bytes())
	// need the digest in uppercase
	for i, c := range dst {
		if c >= 'a' /* && c <= 'f' */ {
			dst[i] = c - 'a' + 'A'
		}
	}
	sum := sha256.Sum256(dst)
	return sum
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
