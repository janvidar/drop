package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"testing"
)

func txid(t *testing.T) TxID {
	t.Helper()
	var tx TxID
	if _, err := rand.Read(tx[:]); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestLooks(t *testing.T) {
	m := NewRequest(txid(t))
	if !Looks(m.Encode()) {
		t.Error("an encoded request should look like STUN")
	}

	notSTUN := [][]byte{
		nil,
		[]byte("short"),
		// ADC UDP search results: the case that actually shares a socket with
		// STUN in a DC client. 'U' is 0x55, whose top two bits are 01.
		[]byte("URES IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KCII SI1234 SL3\n"),
		[]byte("BINF AAAA NIfoo\n"),
		// Right length, wrong cookie.
		make([]byte, 32),
	}
	for _, b := range notSTUN {
		if Looks(b) {
			t.Errorf("%q must not be classified as STUN", firstBytes(b))
		}
	}
}

// The demultiplexing claim the specification makes, checked directly: no ADC
// UDP message can be mistaken for STUN, because ADC messages start with an
// ASCII letter and STUN's top two bits are zero.
func TestADCMessagesNeverLookLikeSTUN(t *testing.T) {
	for _, ctx := range []byte{'U', 'B', 'C', 'D', 'E', 'F', 'H', 'I'} {
		msg := append([]byte{ctx}, []byte("RES AAAABBBBCCCCDDDDEEEEFFFFGGGG\n")...)
		if Looks(msg) {
			t.Errorf("ADC context %q was classified as STUN", ctx)
		}
		if ctx&0xC0 == 0 {
			t.Errorf("ADC context %q has zero top bits, which breaks the demux claim", ctx)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tx := txid(t)
	m := NewRequest(tx)
	m.AddString(AttrUsername, "user")
	m.AddUint32(AttrChangeRequest, ChangeIP|ChangePort)
	m.AddXORAddress(AttrXORMappedAddress, netip.MustParseAddrPort("203.0.113.7:51343"))

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != BindingRequest {
		t.Errorf("type = 0x%04x", got.Type)
	}
	if got.TxID != tx {
		t.Error("transaction id did not survive the round trip")
	}
	if u, _ := got.Username(); u != "user" {
		t.Errorf("username = %q", u)
	}
	ip, port, present := got.ChangeRequest()
	if !present || !ip || !port {
		t.Errorf("change request = (%v, %v, %v)", ip, port, present)
	}
	if ap, ok := got.XORMappedAddress(); !ok || ap.String() != "203.0.113.7:51343" {
		t.Errorf("xor-mapped = %v (ok=%v)", ap, ok)
	}
}

func TestXORAddressRoundTripBothFamilies(t *testing.T) {
	for _, s := range []string{
		"203.0.113.7:51343",
		"0.0.0.0:1",
		"255.255.255.255:65535",
		"[2001:db8::1]:3478",
		"[2a03:b0c0:3:f0:0:2:ce4c:7000]:1511",
	} {
		want := netip.MustParseAddrPort(s)
		m := NewRequest(txid(t))
		m.AddXORAddress(AttrXORMappedAddress, want)

		got, err := Decode(m.Encode())
		if err != nil {
			t.Fatal(err)
		}
		ap, ok := got.XORMappedAddress()
		if !ok || ap != want {
			t.Errorf("%s round-tripped to %v (ok=%v)", s, ap, ok)
		}
	}
}

// The XOR obfuscation must actually be applied: an unobscured address in the
// payload is what middleboxes rewrite, which is the whole reason for it.
func TestXORAddressIsObscured(t *testing.T) {
	m := NewRequest(txid(t))
	m.AddXORAddress(AttrXORMappedAddress, netip.MustParseAddrPort("203.0.113.7:51343"))
	encoded := m.Encode()

	if bytes.Contains(encoded, []byte{203, 0, 113, 7}) {
		t.Error("the address appears unobscured in the encoding")
	}

	// A plain address attribute, by contrast, must not be obscured: RFC 5780
	// defines OTHER-ADDRESS without XOR, and obscuring it would make every
	// behaviour-discovery client read the wrong alternate address.
	m2 := NewRequest(txid(t))
	m2.AddAddress(AttrOtherAddress, netip.MustParseAddrPort("203.0.113.7:3479"))
	if !bytes.Contains(m2.Encode(), []byte{203, 0, 113, 7}) {
		t.Error("OTHER-ADDRESS must not be XOR-obscured")
	}
}

func TestPlainAddressRoundTrip(t *testing.T) {
	want := netip.MustParseAddrPort("198.51.100.11:3479")
	m := NewResponse(&Message{TxID: txid(t)})
	m.AddAddress(AttrOtherAddress, want)

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if ap, ok := got.PlainAddress(AttrOtherAddress); !ok || ap != want {
		t.Errorf("other-address = %v (ok=%v), want %v", ap, ok, want)
	}
}

func TestMessageIntegrity(t *testing.T) {
	key := []byte("correct-horse")

	m := NewRequest(txid(t))
	m.AddString(AttrUsername, "user")
	m.AddMessageIntegrity(key)

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !got.CheckMessageIntegrity(key) {
		t.Fatal("integrity should verify with the right key")
	}
	if got.CheckMessageIntegrity([]byte("wrong-key")) {
		t.Fatal("integrity must not verify with the wrong key")
	}
}

func TestMessageIntegritySHA256(t *testing.T) {
	key := []byte("correct-horse")

	m := NewRequest(txid(t))
	m.AddMessageIntegritySHA256(key)
	m.AddMessageIntegrity(key)

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Has(AttrMessageIntegritySHA256) || !got.Has(AttrMessageIntegrity) {
		t.Fatal("both integrity attributes should be present")
	}
	if !got.CheckMessageIntegrity(key) {
		t.Fatal("both integrity attributes should verify")
	}
	if got.CheckMessageIntegrity([]byte("wrong")) {
		t.Fatal("must not verify with the wrong key")
	}
}

// A message carrying no integrity attribute must never be reported as having
// valid integrity: that is the difference between authenticated and anonymous.
func TestCheckMessageIntegrityRejectsAbsentAttribute(t *testing.T) {
	m := NewRequest(txid(t))
	m.AddString(AttrUsername, "user")

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.CheckMessageIntegrity([]byte("any-key")) {
		t.Fatal("a message with no MESSAGE-INTEGRITY must not verify")
	}
}

// Tampering anywhere before the integrity attribute must invalidate it.
func TestMessageIntegrityDetectsTampering(t *testing.T) {
	key := []byte("secret")
	m := NewRequest(txid(t))
	m.AddString(AttrUsername, "user")
	m.AddXORAddress(AttrXORMappedAddress, netip.MustParseAddrPort("203.0.113.7:1"))
	m.AddMessageIntegrity(key)
	encoded := m.Encode()

	for _, off := range []int{9, 21, 25, 30} {
		if off >= len(encoded) {
			continue
		}
		tampered := append([]byte(nil), encoded...)
		tampered[off] ^= 0xFF

		got, err := Decode(tampered)
		if err != nil {
			continue // a mangled length is caught earlier, which is also fine
		}
		if got.CheckMessageIntegrity(key) {
			t.Errorf("tampering at offset %d was not detected", off)
		}
	}
}

// Truncating an integrity digest must fail rather than compare short.
func TestMessageIntegrityRejectsWrongDigestLength(t *testing.T) {
	m := NewRequest(txid(t))
	m.Add(AttrMessageIntegrity, []byte{1, 2, 3})

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.CheckMessageIntegrity([]byte("k")) {
		t.Fatal("a short digest must not verify")
	}
}

func TestFingerprint(t *testing.T) {
	m := NewRequest(txid(t))
	m.AddString(AttrUsername, "user")
	m.AddFingerprint()

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !got.CheckFingerprint() {
		t.Fatal("fingerprint should verify")
	}

	// Absent is fine; it is an optional attribute.
	plain, _ := Decode(NewRequest(txid(t)).Encode())
	if !plain.CheckFingerprint() {
		t.Error("a message with no fingerprint should pass")
	}
}

func TestFingerprintDetectsTampering(t *testing.T) {
	m := NewRequest(txid(t))
	m.AddString(AttrUsername, "user")
	m.AddFingerprint()
	encoded := m.Encode()

	encoded[25] ^= 0xFF
	got, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.CheckFingerprint() {
		t.Error("tampering was not detected by the fingerprint")
	}
}

// Integrity and fingerprint must coexist: FINGERPRINT follows
// MESSAGE-INTEGRITY and must not disturb it.
func TestIntegrityAndFingerprintTogether(t *testing.T) {
	key := []byte("secret")
	m := NewRequest(txid(t))
	m.AddString(AttrUsername, "user")
	m.AddMessageIntegrity(key)
	m.AddFingerprint()

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !got.CheckMessageIntegrity(key) {
		t.Error("integrity should still verify with a trailing fingerprint")
	}
	if !got.CheckFingerprint() {
		t.Error("fingerprint should verify")
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	valid := NewRequest(txid(t))
	valid.AddString(AttrUsername, "user")
	base := valid.Encode()

	cases := []struct {
		name string
		b    []byte
	}{
		{"nil", nil},
		{"too short", make([]byte, 19)},
		{"top bits set", withByte(base, 0, 0xC0)},
		{"bad cookie", withByte(base, 4, 0x00)},
		{"length not a multiple of four", withLength(base, 3)},
		{"length past the buffer", withLength(base, 0xFFF0)},
		{"attribute past the end", attrPastEnd()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Decode(c.b); err == nil {
				t.Error("expected a decode error")
			}
		})
	}
}

// A declared attribute length larger than the message must be refused rather
// than read past the buffer.
func attrPastEnd() []byte {
	b := make([]byte, headerSize+8)
	binary.BigEndian.PutUint16(b[0:2], BindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 8)
	binary.BigEndian.PutUint32(b[4:8], MagicCookie)
	binary.BigEndian.PutUint16(b[20:22], uint16(AttrUsername))
	binary.BigEndian.PutUint16(b[22:24], 0xFF00) // claims far more than exists
	return b
}

func TestUnknownRequiredAttributes(t *testing.T) {
	m := NewRequest(txid(t))
	m.Add(0x7FFF, []byte{1, 2, 3, 4}) // comprehension-required, unknown
	m.Add(0x8FFF, []byte{1, 2, 3, 4}) // comprehension-optional, unknown
	m.AddString(AttrUsername, "user") // known

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	unknown := got.UnknownRequired()
	if len(unknown) != 1 || unknown[0] != 0x7FFF {
		t.Errorf("unknown required = %v, want [0x7FFF]", unknown)
	}
}

func TestErrorResponse(t *testing.T) {
	req := NewRequest(txid(t))
	m := NewError(req, CodeUnauthorized, "Unauthorized")

	got, err := Decode(m.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != BindingError {
		t.Errorf("type = 0x%04x, want an error response", got.Type)
	}
	if got.TxID != req.TxID {
		t.Error("an error response must echo the transaction id")
	}
	code, reason, ok := got.ErrorCode()
	if !ok || code != 401 || reason != "Unauthorized" {
		t.Errorf("error = (%d, %q, %v)", code, reason, ok)
	}
}

// Attribute values that are not a multiple of four must still round-trip:
// the padding is not part of the value.
func TestOddLengthAttributePadding(t *testing.T) {
	for _, s := range []string{"a", "ab", "abc", "abcd", "abcde"} {
		m := NewRequest(txid(t))
		m.AddString(AttrUsername, s)
		m.AddString(AttrSoftware, "after") // ensure the next attribute still parses

		got, err := Decode(m.Encode())
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if u, _ := got.Username(); u != s {
			t.Errorf("username %q round-tripped as %q", s, u)
		}
		if sw, ok := got.Get(AttrSoftware); !ok || string(sw) != "after" {
			t.Errorf("%q: the following attribute was lost", s)
		}
	}
}

// Decode must never panic, whatever arrives on the socket.
func FuzzDecode(f *testing.F) {
	m := NewRequest(TxID{1, 2, 3})
	m.AddString(AttrUsername, "user")
	m.AddMessageIntegrity([]byte("k"))
	m.AddFingerprint()
	f.Add(m.Encode())
	f.Add([]byte("URES AAAA\n"))
	f.Add(make([]byte, 20))

	f.Fuzz(func(t *testing.T, b []byte) {
		msg, err := Decode(b)
		if err != nil {
			return
		}
		// Every accessor must also be safe on anything that decoded.
		msg.XORMappedAddress()
		msg.PlainAddress(AttrOtherAddress)
		msg.ChangeRequest()
		msg.Username()
		msg.ErrorCode()
		msg.UnknownRequired()
		msg.CheckFingerprint()
		msg.CheckMessageIntegrity([]byte("key"))
		msg.Encode()
	})
}

func withByte(b []byte, off int, v byte) []byte {
	out := append([]byte(nil), b...)
	out[off] = v
	return out
}

func withLength(b []byte, l uint16) []byte {
	out := append([]byte(nil), b...)
	binary.BigEndian.PutUint16(out[2:4], l)
	return out
}

func firstBytes(b []byte) string {
	if len(b) > 16 {
		return string(b[:16])
	}
	return string(b)
}
