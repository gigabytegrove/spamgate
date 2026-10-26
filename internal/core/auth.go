package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// PBKDF2-HMAC-SHA256, RFC 8018. Kept dependency-free for portable builds.
const passwordRounds = 250000

func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	result := make([]byte, 0, keyLen)
	for block := uint32(1); len(result) < keyLen; block++ {
		msg := append(append([]byte(nil), salt...), byte(block>>24), byte(block>>16), byte(block>>8), byte(block))
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(msg)
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}
func MakePassword(password string) (salt, hash string, err error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", "", errors.New("password must be 12–1024 bytes")
	}
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return
	}
	out := pbkdf2([]byte(password), b, passwordRounds, 32)
	return hex.EncodeToString(b), hex.EncodeToString(out), nil
}
func CheckPassword(password string, u User) bool {
	salt, e := hex.DecodeString(u.Salt)
	if e != nil || len(salt) != 16 {
		return false
	}
	want, e := hex.DecodeString(u.PasswordHash)
	if e != nil || len(want) != 32 {
		return false
	}
	got := pbkdf2([]byte(password), salt, passwordRounds, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func MakeToken() (string, string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", "e", e
	}
	token := "sg_" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(h[:]), nil
}
func CheckToken(v string, t Token) bool {
	if !strings.HasPrefix(v, "sg_") {
		return false
	}
	h := sha256.Sum256([]byte(v))
	want, e := hex.DecodeString(t.Hash)
	return e == nil && len(want) == 32 && subtle.ConstantTimeCompare(h[:], want) == 1
}
func equalEmail(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
