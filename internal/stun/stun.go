// Package stun implements the subset of STUN that DROP needs: RFC 8489
// Binding requests and responses with short-term credentials, plus the RFC
// 5780 attributes for NAT behaviour discovery.
//
// It is implemented here rather than taken from a library for three reasons.
// The current maintained Go STUN libraries require a newer toolchain than this
// project targets; none of them ship the RFC 5780 attributes, which is
// precisely the half of STUN that DROP depends on and that is missing from
// almost every deployed server; and this code parses unauthenticated datagrams
// from the public internet, so it is worth keeping small, bounds-checked and
// directly reviewable.
package stun

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"net/netip"
)

// MagicCookie identifies a STUN message and never varies (RFC 8489 section 5).
const MagicCookie uint32 = 0x2112A442

// headerSize is the fixed STUN header: type, length, cookie, transaction id.
const headerSize = 20

// Message classes and methods, pre-combined into the type values used here.
const (
	BindingRequest    uint16 = 0x0001
	BindingIndication uint16 = 0x0011
	BindingResponse   uint16 = 0x0101
	BindingError      uint16 = 0x0111
)

// AttrType is a STUN attribute type.
//
// Types below 0x8000 are comprehension-required: an agent that does not
// understand one must reject the message. Types at or above 0x8000 are
// comprehension-optional and may be ignored (RFC 8489 section 14).
type AttrType uint16

const (
	AttrMappedAddress          AttrType = 0x0001
	AttrUsername               AttrType = 0x0006
	AttrMessageIntegrity       AttrType = 0x0008
	AttrErrorCode              AttrType = 0x0009
	AttrUnknownAttributes      AttrType = 0x000A
	AttrRealm                  AttrType = 0x0014
	AttrNonce                  AttrType = 0x0015
	AttrMessageIntegritySHA256 AttrType = 0x001C
	AttrXORMappedAddress       AttrType = 0x0020
	AttrSoftware               AttrType = 0x8022
	AttrAlternateServer        AttrType = 0x8023
	AttrFingerprint            AttrType = 0x8028

	// RFC 5780, NAT behaviour discovery.
	AttrChangeRequest  AttrType = 0x0003
	AttrPadding        AttrType = 0x0026
	AttrResponsePort   AttrType = 0x0027
	AttrResponseOrigin AttrType = 0x802b
	AttrOtherAddress   AttrType = 0x802c

	// AttrDropProbe marks a Binding Request as a DROP unsolicited inbound
	// probe, so a client knows to apply the DROP response rules rather than
	// treating it as ordinary STUN traffic.
	//
	// Provisional and unregistered. It sits in the comprehension-optional
	// range so a stock STUN agent ignores it rather than rejecting the
	// message.
	AttrDropProbe AttrType = 0xFF0D
)

// Comprehension-required attributes this implementation understands. Anything
// else below 0x8000 must be reported back in UNKNOWN-ATTRIBUTES.
var knownRequired = map[AttrType]bool{
	AttrMappedAddress:          true,
	AttrUsername:               true,
	AttrMessageIntegrity:       true,
	AttrErrorCode:              true,
	AttrUnknownAttributes:      true,
	AttrRealm:                  true,
	AttrNonce:                  true,
	AttrMessageIntegritySHA256: true,
	AttrXORMappedAddress:       true,
	AttrChangeRequest:          true,
	AttrPadding:                true,
	AttrResponsePort:           true,
}

// CHANGE-REQUEST flags (RFC 5780 section 7.2).
const (
	ChangeIP   uint32 = 0x04
	ChangePort uint32 = 0x02
)

// Error codes used by this implementation.
const (
	CodeBadRequest   = 400
	CodeUnauthorized = 401
	CodeUnknownAttr  = 420
)

// Parse errors. They are distinguishable so a server can decide between
// answering with an error and dropping the datagram entirely.
var (
	ErrTooShort     = errors.New("stun: message shorter than the header")
	ErrNotSTUN      = errors.New("stun: leading bits or magic cookie do not match")
	ErrBadLength    = errors.New("stun: declared length is invalid")
	ErrTruncated    = errors.New("stun: attribute runs past the end of the message")
	ErrBadAttribute = errors.New("stun: malformed attribute")
)

// TxID is a STUN transaction identifier.
type TxID [12]byte

// Attribute is one type-length-value.
type Attribute struct {
	Type  AttrType
	Value []byte
}

// Message is a decoded STUN message.
type Message struct {
	Type  uint16
	TxID  TxID
	Attrs []Attribute

	// raw is the exact bytes this message was decoded from, retained because
	// MESSAGE-INTEGRITY must be verified over the original encoding: a
	// re-encoding could differ in attribute order or padding and would not
	// validate even when the message is genuine.
	raw []byte
}

// Looks reports whether b plausibly begins a STUN message.
//
// This is the demultiplexing test for a socket that carries both STUN and
// something else. The two leading bits of every STUN message are zero and the
// magic cookie is fixed, which is what makes STUN separable from ADC's UDP
// messages: those begin with an ASCII letter, whose top bits are never 00.
func Looks(b []byte) bool {
	if len(b) < headerSize {
		return false
	}
	if b[0]&0xC0 != 0 {
		return false
	}
	return binary.BigEndian.Uint32(b[4:8]) == MagicCookie
}

// Decode parses a STUN message.
//
// Every length is checked against the remaining buffer before use. This runs
// on unauthenticated datagrams from anywhere on the internet.
func Decode(b []byte) (*Message, error) {
	if len(b) < headerSize {
		return nil, ErrTooShort
	}
	if b[0]&0xC0 != 0 {
		return nil, ErrNotSTUN
	}
	if binary.BigEndian.Uint32(b[4:8]) != MagicCookie {
		return nil, ErrNotSTUN
	}

	msgType := binary.BigEndian.Uint16(b[0:2])
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length%4 != 0 {
		return nil, ErrBadLength
	}
	if headerSize+length > len(b) {
		return nil, ErrTruncated
	}

	m := &Message{Type: msgType}
	copy(m.TxID[:], b[8:20])
	// Trailing bytes beyond the declared length are not part of the message.
	m.raw = b[:headerSize+length]

	body := m.raw[headerSize:]
	for off := 0; off < len(body); {
		if off+4 > len(body) {
			return nil, ErrBadAttribute
		}
		atyp := AttrType(binary.BigEndian.Uint16(body[off : off+2]))
		alen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4

		if off+alen > len(body) {
			return nil, ErrTruncated
		}
		value := body[off : off+alen]
		off += alen

		// Attributes are padded to a four-byte boundary; the padding is not
		// part of the value and may be absent at the very end of a message.
		if pad := (4 - alen%4) % 4; pad > 0 {
			if off+pad > len(body) {
				off = len(body)
			} else {
				off += pad
			}
		}

		m.Attrs = append(m.Attrs, Attribute{Type: atyp, Value: value})
	}
	return m, nil
}

// Get returns the first attribute of the given type.
func (m *Message) Get(t AttrType) ([]byte, bool) {
	for _, a := range m.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// Has reports whether the attribute is present.
func (m *Message) Has(t AttrType) bool {
	_, ok := m.Get(t)
	return ok
}

// UnknownRequired lists comprehension-required attributes this implementation
// does not understand, which a server must report with a 420.
func (m *Message) UnknownRequired() []AttrType {
	var out []AttrType
	for _, a := range m.Attrs {
		if a.Type < 0x8000 && !knownRequired[a.Type] {
			out = append(out, a.Type)
		}
	}
	return out
}

// Add appends an attribute.
func (m *Message) Add(t AttrType, v []byte) {
	m.Attrs = append(m.Attrs, Attribute{Type: t, Value: v})
}

// AddUint32 appends a four-byte attribute.
func (m *Message) AddUint32(t AttrType, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	m.Add(t, b)
}

// AddString appends a textual attribute.
func (m *Message) AddString(t AttrType, s string) { m.Add(t, []byte(s)) }

// Encode serialises the message.
func (m *Message) Encode() []byte {
	body := make([]byte, 0, 128)
	for _, a := range m.Attrs {
		body = appendAttr(body, a)
	}
	out := make([]byte, headerSize, headerSize+len(body))
	binary.BigEndian.PutUint16(out[0:2], m.Type)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	binary.BigEndian.PutUint32(out[4:8], MagicCookie)
	copy(out[8:20], m.TxID[:])
	return append(out, body...)
}

func appendAttr(dst []byte, a Attribute) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(a.Type))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(a.Value)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, a.Value...)
	for i := 0; i < (4-len(a.Value)%4)%4; i++ {
		dst = append(dst, 0)
	}
	return dst
}

// --- addresses --------------------------------------------------------------

const (
	familyIPv4 = 0x01
	familyIPv6 = 0x02
)

// AppendXORAddress encodes an address as XOR-MAPPED-ADDRESS style, obscured
// with the magic cookie and transaction id. The obfuscation exists so that
// middleboxes rewriting addresses in payloads do not silently corrupt it.
func (m *Message) AddXORAddress(t AttrType, ap netip.AddrPort) {
	m.Add(t, encodeAddr(ap, true, m.TxID))
}

// AddAddress encodes a plain (non-XOR) address, used by RESPONSE-ORIGIN and
// OTHER-ADDRESS, which RFC 5780 defines without obfuscation.
func (m *Message) AddAddress(t AttrType, ap netip.AddrPort) {
	m.Add(t, encodeAddr(ap, false, m.TxID))
}

func encodeAddr(ap netip.AddrPort, xor bool, tx TxID) []byte {
	addr := ap.Addr().Unmap()
	port := ap.Port()

	var raw []byte
	family := byte(familyIPv4)
	if addr.Is4() {
		a := addr.As4()
		raw = a[:]
	} else {
		family = familyIPv6
		a := addr.As16()
		raw = a[:]
	}

	out := make([]byte, 4+len(raw))
	out[0] = 0
	out[1] = family

	if xor {
		port ^= uint16(MagicCookie >> 16)
	}
	binary.BigEndian.PutUint16(out[2:4], port)

	copy(out[4:], raw)
	if xor {
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], MagicCookie)
		copy(mask[4:], tx[:])
		for i := range raw {
			out[4+i] ^= mask[i]
		}
	}
	return out
}

// DecodeAddress reads an address attribute.
func DecodeAddress(v []byte, xor bool, tx TxID) (netip.AddrPort, error) {
	if len(v) < 4 {
		return netip.AddrPort{}, ErrBadAttribute
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4])
	if xor {
		port ^= uint16(MagicCookie >> 16)
	}

	var size int
	switch family {
	case familyIPv4:
		size = 4
	case familyIPv6:
		size = 16
	default:
		return netip.AddrPort{}, ErrBadAttribute
	}
	if len(v) < 4+size {
		return netip.AddrPort{}, ErrBadAttribute
	}

	raw := make([]byte, size)
	copy(raw, v[4:4+size])
	if xor {
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], MagicCookie)
		copy(mask[4:], tx[:])
		for i := range raw {
			raw[i] ^= mask[i]
		}
	}

	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, ErrBadAttribute
	}
	return netip.AddrPortFrom(addr.Unmap(), port), nil
}

// XORMappedAddress returns the decoded XOR-MAPPED-ADDRESS.
func (m *Message) XORMappedAddress() (netip.AddrPort, bool) {
	v, ok := m.Get(AttrXORMappedAddress)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap, err := DecodeAddress(v, true, m.TxID)
	return ap, err == nil
}

// PlainAddress returns a decoded non-XOR address attribute, such as
// OTHER-ADDRESS or RESPONSE-ORIGIN.
func (m *Message) PlainAddress(t AttrType) (netip.AddrPort, bool) {
	v, ok := m.Get(t)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap, err := DecodeAddress(v, false, m.TxID)
	return ap, err == nil
}

// --- integrity --------------------------------------------------------------

// AddMessageIntegrity appends MESSAGE-INTEGRITY (HMAC-SHA1) computed with the
// short-term credential key.
//
// RFC 8489 section 14.5: the HMAC covers the message up to but not including
// this attribute, with the header's length field adjusted as though the
// attribute were already present. Everything after it is excluded, which is
// why FINGERPRINT may follow but nothing else may.
func (m *Message) AddMessageIntegrity(key []byte) {
	partial := m.encodeForIntegrity(sha1.Size)
	mac := hmac.New(sha1.New, key)
	mac.Write(partial)
	m.Add(AttrMessageIntegrity, mac.Sum(nil))
}

// AddMessageIntegritySHA256 appends MESSAGE-INTEGRITY-SHA256.
func (m *Message) AddMessageIntegritySHA256(key []byte) {
	partial := m.encodeForIntegrity(sha256.Size)
	mac := hmac.New(sha256.New, key)
	mac.Write(partial)
	m.Add(AttrMessageIntegritySHA256, mac.Sum(nil))
}

// encodeForIntegrity renders the current attributes with the header length
// extended by an attribute of the given digest size.
func (m *Message) encodeForIntegrity(digestSize int) []byte {
	body := make([]byte, 0, 128)
	for _, a := range m.Attrs {
		body = appendAttr(body, a)
	}
	out := make([]byte, headerSize, headerSize+len(body))
	binary.BigEndian.PutUint16(out[0:2], m.Type)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)+4+digestSize))
	binary.BigEndian.PutUint32(out[4:8], MagicCookie)
	copy(out[8:20], m.TxID[:])
	return append(out, body...)
}

// CheckMessageIntegrity verifies MESSAGE-INTEGRITY, and
// MESSAGE-INTEGRITY-SHA256 when present, against key.
//
// It reports false when no integrity attribute is present at all: a caller
// asking to verify integrity must never be told "valid" for an unauthenticated
// message.
func (m *Message) CheckMessageIntegrity(key []byte) bool {
	if m.raw == nil {
		return false
	}
	checked := false

	if v, ok := m.Get(AttrMessageIntegritySHA256); ok {
		if !m.checkOne(AttrMessageIntegritySHA256, v, key, sha256.New, sha256.Size) {
			return false
		}
		checked = true
	}
	if v, ok := m.Get(AttrMessageIntegrity); ok {
		if !m.checkOne(AttrMessageIntegrity, v, key, sha1.New, sha1.Size) {
			return false
		}
		checked = true
	}
	return checked
}

// checkOne recomputes one integrity attribute over the original bytes.
func (m *Message) checkOne(t AttrType, got, key []byte, h func() hash.Hash, size int) bool {
	if len(got) != size {
		return false
	}
	off, ok := m.attrOffset(t)
	if !ok {
		return false
	}

	// Reconstruct the exact input: original bytes up to the attribute, with
	// the length field rewritten to end just past it.
	partial := make([]byte, off)
	copy(partial, m.raw[:off])
	binary.BigEndian.PutUint16(partial[2:4], uint16(off-headerSize+4+size))

	mac := hmac.New(h, key)
	mac.Write(partial)
	return hmac.Equal(mac.Sum(nil), got)
}

// attrOffset finds where an attribute's header starts in the original bytes.
func (m *Message) attrOffset(want AttrType) (int, bool) {
	body := m.raw[headerSize:]
	for off := 0; off+4 <= len(body); {
		atyp := AttrType(binary.BigEndian.Uint16(body[off : off+2]))
		alen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if atyp == want {
			return headerSize + off, true
		}
		off += 4 + alen + (4-alen%4)%4
	}
	return 0, false
}

// AddFingerprint appends FINGERPRINT, which must be the last attribute.
//
// It is a CRC-32 of the message with the length field adjusted to include the
// attribute, XORed with a constant so that a bare CRC cannot be mistaken for
// one (RFC 8489 section 14.7).
func (m *Message) AddFingerprint() {
	partial := m.encodeForIntegrity(4)
	// encodeForIntegrity reserves 4 + size; FINGERPRINT's value is 4 bytes, so
	// the reservation is already correct.
	crc := crc32.ChecksumIEEE(partial) ^ 0x5354554e
	m.AddUint32(AttrFingerprint, crc)
}

// CheckFingerprint verifies FINGERPRINT if present. A message without one
// passes: the attribute is optional.
func (m *Message) CheckFingerprint() bool {
	v, ok := m.Get(AttrFingerprint)
	if !ok {
		return true
	}
	if len(v) != 4 {
		return false
	}
	off, ok := m.attrOffset(AttrFingerprint)
	if !ok {
		return false
	}
	partial := make([]byte, off)
	copy(partial, m.raw[:off])
	binary.BigEndian.PutUint16(partial[2:4], uint16(off-headerSize+8))

	want := crc32.ChecksumIEEE(partial) ^ 0x5354554e
	return binary.BigEndian.Uint32(v) == want
}

// --- construction helpers ---------------------------------------------------

// NewRequest builds a Binding Request with a fresh transaction id.
func NewRequest(tx TxID) *Message {
	return &Message{Type: BindingRequest, TxID: tx}
}

// NewResponse builds a success response matching a request.
func NewResponse(req *Message) *Message {
	return &Message{Type: BindingResponse, TxID: req.TxID}
}

// NewError builds an error response.
func NewError(req *Message, code int, reason string) *Message {
	m := &Message{Type: BindingError, TxID: req.TxID}
	// ERROR-CODE: two reserved bytes, then class and number, then the reason
	// phrase (RFC 8489 section 14.8).
	v := make([]byte, 4, 4+len(reason))
	v[2] = byte(code / 100)
	v[3] = byte(code % 100)
	v = append(v, reason...)
	m.Add(AttrErrorCode, v)
	return m
}

// ErrorCode returns the numeric code of an error response.
func (m *Message) ErrorCode() (int, string, bool) {
	v, ok := m.Get(AttrErrorCode)
	if !ok || len(v) < 4 {
		return 0, "", false
	}
	return int(v[2])*100 + int(v[3]), string(v[4:]), true
}

// ChangeRequest returns the CHANGE-REQUEST flags.
func (m *Message) ChangeRequest() (changeIP, changePort bool, present bool) {
	v, ok := m.Get(AttrChangeRequest)
	if !ok || len(v) != 4 {
		return false, false, false
	}
	flags := binary.BigEndian.Uint32(v)
	return flags&ChangeIP != 0, flags&ChangePort != 0, true
}

// Username returns the USERNAME attribute as a string.
func (m *Message) Username() (string, bool) {
	v, ok := m.Get(AttrUsername)
	if !ok {
		return "", false
	}
	return string(v), true
}

func (m *Message) String() string {
	return fmt.Sprintf("stun.Message{type=0x%04x attrs=%d}", m.Type, len(m.Attrs))
}
