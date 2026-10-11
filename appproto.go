package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// tlsServerName returns the SNI from a TLS ClientHello, or "" if the payload is
// not one or the extension is beyond the bytes available.
func tlsServerName(b []byte) string {
	// TLS record: type(1)=0x16 handshake, version(2), length(2)
	if len(b) < 5+4 || b[0] != 0x16 || b[1] != 0x03 {
		return ""
	}
	b = b[5:]
	// Handshake: type(1)=0x01 ClientHello, length(3)
	if b[0] != 0x01 {
		return ""
	}
	b = b[4:]
	// client version(2) random(32)
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	// session id
	if len(b) < 1 {
		return ""
	}
	n := int(b[0])
	b = b[1:]
	if len(b) < n {
		return ""
	}
	b = b[n:]
	// cipher suites
	if len(b) < 2 {
		return ""
	}
	n = int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < n {
		return ""
	}
	b = b[n:]
	// compression methods
	if len(b) < 1 {
		return ""
	}
	n = int(b[0])
	b = b[1:]
	if len(b) < n {
		return ""
	}
	b = b[n:]
	// extensions
	if len(b) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) > extLen {
		b = b[:extLen]
	}
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if len(b) < l {
			return ""
		}
		if typ == 0 { // server_name
			ext := b[:l]
			if len(ext) < 5 {
				return ""
			}
			ext = ext[2:]    // list length
			if ext[0] != 0 { // host_name
				return ""
			}
			nl := int(binary.BigEndian.Uint16(ext[1:]))
			ext = ext[3:]
			if len(ext) < nl {
				return ""
			}
			return string(ext[:nl])
		}
		b = b[l:]
	}
	return ""
}

var httpMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "), []byte("CONNECT "), []byte("PATCH ")}

// httpRequest returns the Host header and the request line of a plaintext HTTP request.
func httpRequest(b []byte) (host, line string) {
	ok := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			ok = true
			break
		}
	}
	if !ok {
		return "", ""
	}
	if len(b) > 1024 {
		b = b[:1024]
	}
	lines := strings.Split(string(b), "\r\n")
	line = lines[0]
	if i := strings.LastIndex(line, " HTTP/"); i > 0 {
		line = line[:i]
	}
	for _, l := range lines[1:] {
		if l == "" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "Host") {
			host = strings.TrimSpace(v)
			break
		}
	}
	return host, line
}
