package vless

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseUUID(t *testing.T) {
	got, err := parseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	want := [16]byte{0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11}
	if got != want {
		t.Fatalf("parseUUID = %x, want %x", got, want)
	}

	for _, bad := range []string{"", "not-a-uuid", "b831381d6324", "zzzzzzzz-6324-4d53-ad4f-8cda48b30811"} {
		if _, err := parseUUID(bad); err == nil {
			t.Errorf("parseUUID(%q) expected error, got nil", bad)
		}
	}
}

func TestEncodeRequestHeaderDomain(t *testing.T) {
	uuid, _ := parseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	hdr, err := encodeRequestHeader(uuid, "example.com", 443)
	if err != nil {
		t.Fatalf("encodeRequestHeader: %v", err)
	}

	// version(1) + uuid(16) + addonLen(1) + cmd(1) + port(2) + atyp(1) +
	// domainLen(1) + "example.com"(11)
	wantLen := 1 + 16 + 1 + 1 + 2 + 1 + 1 + len("example.com")
	if len(hdr) != wantLen {
		t.Fatalf("header length = %d, want %d", len(hdr), wantLen)
	}
	if hdr[0] != protocolVersion {
		t.Errorf("version = %d, want %d", hdr[0], protocolVersion)
	}
	if !bytes.Equal(hdr[1:17], uuid[:]) {
		t.Errorf("uuid mismatch")
	}
	if hdr[17] != 0 {
		t.Errorf("addon length = %d, want 0", hdr[17])
	}
	if hdr[18] != cmdTCP {
		t.Errorf("command = %d, want %d", hdr[18], cmdTCP)
	}
	if port := binary.BigEndian.Uint16(hdr[19:21]); port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if hdr[21] != atypDomain {
		t.Errorf("atyp = %d, want %d (domain)", hdr[21], atypDomain)
	}
	if hdr[22] != byte(len("example.com")) {
		t.Errorf("domain length = %d, want %d", hdr[22], len("example.com"))
	}
	if string(hdr[23:]) != "example.com" {
		t.Errorf("domain = %q, want example.com", hdr[23:])
	}
}

func TestEncodeRequestHeaderIPv4(t *testing.T) {
	uuid, _ := parseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	hdr, err := encodeRequestHeader(uuid, "1.2.3.4", 80)
	if err != nil {
		t.Fatalf("encodeRequestHeader: %v", err)
	}
	if hdr[21] != atypIPv4 {
		t.Fatalf("atyp = %d, want %d (IPv4)", hdr[21], atypIPv4)
	}
	if got := hdr[22:26]; !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("ipv4 = %v, want [1 2 3 4]", got)
	}
}

func TestConsumeResponseHeader(t *testing.T) {
	// version=0, addonLen=2, two addon bytes, then payload "hi".
	stream := bytes.NewReader([]byte{0x00, 0x02, 0xaa, 0xbb, 'h', 'i'})
	if err := consumeResponseHeader(stream); err != nil {
		t.Fatalf("consumeResponseHeader: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := stream.Read(buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("payload = %q, want hi", buf)
	}

	// Wrong version should error.
	bad := bytes.NewReader([]byte{0x01, 0x00})
	if err := consumeResponseHeader(bad); err == nil {
		t.Fatalf("expected error on bad version")
	}
}
