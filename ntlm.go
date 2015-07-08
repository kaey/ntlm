// Copyright 2015 Konstantin Kulikov. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ntlm is an NTLMv1 client implementation.
//
// NTLM session started with sending Negotiate() to server.
// Server then responds with challenge, use ParseChallenge to get neccecary bits from it.
// Then use Authenticate() to generate authentication string.
package ntlm

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

const (
	signature = "NTLMSSP\x00"
)

const (
	negotiateOEM  uint32 = 0x00000002
	requestTarget uint32 = 0x00000004
	negotiateNTLM uint32 = 0x00000200
)

var (
	putUint16 = binary.LittleEndian.PutUint16
	getUint16 = binary.LittleEndian.Uint16
	putUint32 = binary.LittleEndian.PutUint32
	getUint32 = binary.LittleEndian.Uint32
)

func putUint8(b []byte, n uint8) {
	b[0] = n
}

func getUint8(b []byte) uint8 {
	return uint8(b[0])
}

func putString(b []byte, s string) {
	for i := 0; i < len(b) && i < len(s); i++ {
		b[i] = s[i]
	}
}

func getString(b []byte) string {
	return string(b)
}

// Negotiate generates Negotiate message.
func Negotiate() []byte {
	b := make([]byte, 16)
	flags := negotiateOEM | requestTarget | negotiateNTLM

	putString(b[0:8], signature) // Signature
	putUint32(b[8:12], 1)        // Message type 1
	putUint32(b[12:16], flags)   // Flags

	return b
}

// ParseChallenge parses challenge provided by peer.
func ParseChallenge(b []byte) ([]byte, error) {
	if len(b) < 40 {
		return nil, fmt.Errorf("ntlm.ParseChallenge: expected msg len >40, got %v", len(b))
	}

	sig := getString(b[0:8]) // Signature
	if signature != sig {
		return nil, fmt.Errorf("ntlm.ParseChallenge: expected signature %q, got %q", signature, sig)
	}

	typ := getUint32(b[8:12]) // Message type
	if typ != 2 {
		return nil, fmt.Errorf("ntlm.ParseChallenge: expected msg type 2, got %v", typ)
	}

	_ = b[12:20]            // Target len/maxlen/offset (ignored)
	_ = getUint32(b[20:24]) // Flags (ignored)
	challenge := make([]byte, 8)
	copy(challenge, b[24:32]) // Challenge
	_ = b[32:40]              // Context (ignored)

	return challenge, nil
}

// Authenticate generates auth message.
func Authenticate(username, password, domain string, challenge []byte) []byte {
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}

	host = strings.ToUpper(host)
	domain = strings.ToUpper(domain)

	offset := 52
	lm := string(make([]byte, 24)) // LM is not needed and is insecure, just fill it with 24 zero bytes.
	nt := calcNT(challenge, password)
	b := make([]byte, offset+len(lm)+len(nt)+len(domain)+len(username)+len(host))

	putString(b[0:8], signature) // Signature
	putUint32(b[8:12], 3)        // Message type 3

	putUint16(b[12:14], uint16(len(lm)))    // lm len
	putUint16(b[14:16], uint16(len(lm)))    // lm max len
	putUint32(b[16:20], uint32(offset))     // lm offset
	putString(b[offset:offset+len(lm)], lm) // lm data
	offset += len(lm)

	putUint16(b[12:14], uint16(len(nt)))    // nt len
	putUint16(b[14:16], uint16(len(nt)))    // nt max len
	putUint32(b[16:20], uint32(offset))     // nt offset
	putString(b[offset:offset+len(nt)], nt) // nt data
	offset += len(nt)

	putUint16(b[28:30], uint16(len(domain)))        // domain len
	putUint16(b[30:32], uint16(len(domain)))        // domain max len
	putUint32(b[32:36], uint32(offset))             // domain offset
	putString(b[offset:offset+len(domain)], domain) // domain data
	offset += len(domain)

	putUint16(b[36:38], uint16(len(username)))          // user len
	putUint16(b[38:40], uint16(len(username)))          // user max len
	putUint32(b[40:44], uint32(offset))                 // user offset
	putString(b[offset:offset+len(username)], username) // user data
	offset += len(username)

	putUint16(b[44:46], uint16(len(host)))      // host len
	putUint16(b[46:48], uint16(len(host)))      // host max len
	putUint32(b[48:52], uint32(offset))         // host offset
	putString(b[offset:offset+len(host)], host) // host data
	offset += len(host)

	return b[:offset]
}

func calcNT(challenge []byte, pass string) string {
	ntlmpass, _, _ := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder(), []byte(pass))
	hash := make([]byte, 21)
	res := make([]byte, 24)

	h := md4.New()
	h.Write(ntlmpass)
	h.Sum(hash[:0])

	blk, _ := des.NewCipher(convDes7to8(hash[0:7]))
	blk.Encrypt(res[0:8], challenge)

	blk, _ = des.NewCipher(convDes7to8(hash[7:14]))
	blk.Encrypt(res[8:16], challenge)

	blk, _ = des.NewCipher(convDes7to8(hash[14:21]))
	blk.Encrypt(res[16:24], challenge)

	return string(res)
}

// ConvDes7to8 adds parity bit after every 7th bit.
func convDes7to8(src []byte) []byte {
	res := make([]byte, 8)

	res[0] = src[0] & 0xFE
	res[1] = (src[0]<<7)&0xFF | (src[1]>>1)&0xFE
	res[2] = (src[1]<<6)&0xFF | (src[2]>>2)&0xFE
	res[3] = (src[2]<<5)&0xFF | (src[3]>>3)&0xFE
	res[4] = (src[3]<<4)&0xFF | (src[4]>>4)&0xFE
	res[5] = (src[4]<<3)&0xFF | (src[5]>>5)&0xFE
	res[6] = (src[5]<<2)&0xFF | (src[6]>>6)&0xFE
	res[7] = (src[6] << 1) & 0xFF

	for i := range res {
		if ((res[i]>>7 ^ res[i]>>6 ^ res[i]>>5 ^ res[i]>>4 ^ res[i]>>3 ^ res[i]>>2 ^ res[i]>>1) & 0x01) == 0 {
			res[i] |= 0x01
		}
	}

	return res
}
