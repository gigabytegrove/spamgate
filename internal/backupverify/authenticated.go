package backupverify

import (
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "bytes"
 "errors"
 "fmt"
 "io"
 "strings"
)

// SignedManifest binds an inventory to an operator-held secret. The secret
// must be stored separately from the backup and must never be logged.
type SignedManifest struct {
 Manifest Manifest `json:"manifest"`
 MAC string `json:"hmac_sha256"`
}

const MinAuthenticationKeyBytes = 32

func canonicalManifest(m Manifest) ([]byte, error) {
 if err := ValidateManifest(m); err != nil { return nil, err }
 // JSON encodes fields in a deterministic order for this fixed schema.
 return json.Marshal(m)
}

func computeMAC(key, payload []byte) string {
 h := hmac.New(sha256.New, key)
 h.Write([]byte("SpamGate backup manifest v1\x00"))
 h.Write(payload)
 return hex.EncodeToString(h.Sum(nil))
}

func validateKey(key []byte) error {
 if len(key) < MinAuthenticationKeyBytes { return fmt.Errorf("backup authentication key must be at least %d bytes", MinAuthenticationKeyBytes) }
 return nil
}

// SignManifest creates an authenticated inventory. Signing is not a substitute
// for creating a consistent snapshot of the live database and mail state.
func SignManifest(m Manifest, key []byte) (SignedManifest, error) {
 if err := validateKey(key); err != nil { return SignedManifest{}, err }
 payload, err := canonicalManifest(m)
 if err != nil { return SignedManifest{}, err }
 return SignedManifest{Manifest:m, MAC:computeMAC(key,payload)},nil
}

// AuthenticateManifest rejects tampering before any backup file is opened.
func AuthenticateManifest(s SignedManifest, key []byte) error {
 if err := validateKey(key); err != nil { return err }
 payload, err := canonicalManifest(s.Manifest)
 if err != nil { return err }
 if len(s.MAC) != 64 || strings.ToLower(s.MAC) != s.MAC { return errors.New("invalid backup manifest authenticator") }
 provided, err := hex.DecodeString(s.MAC)
 if err != nil || len(provided) != sha256.Size { return errors.New("invalid backup manifest authenticator") }
 expected, err := hex.DecodeString(computeMAC(key,payload))
 if err != nil { return err }
 if !hmac.Equal(provided,expected) { return errors.New("backup manifest authentication failed") }
 return nil
}

// VerifyAuthenticated checks the MAC first, then verifies each file against
// the authenticated inventory. It never changes the running mail server.
func VerifyAuthenticated(root string, signed SignedManifest, key []byte) (Report,error) {
 if err := AuthenticateManifest(signed,key); err != nil { return Report{},err }
 return Verify(root,signed.Manifest)
}

// DecodeSignedManifest rejects unknown fields, trailing JSON, and oversized
// input before authenticating. Callers must supply the secret separately.
const MaxSignedManifestJSONBytes = 16 << 20

func DecodeSignedManifest(r io.Reader) (SignedManifest,error) {
 var signed SignedManifest
 // Read one byte past the bound so even whitespace-only overages fail.
 data,err:=io.ReadAll(io.LimitReader(r,MaxSignedManifestJSONBytes+1))
 if err!=nil{return signed,err}
 if len(data)>MaxSignedManifestJSONBytes{return signed,errors.New("backup manifest JSON exceeds size limit")}
 if err:=validateUniqueJSONKeys(data);err!=nil{return signed,err}
 decoder:=json.NewDecoder(bytes.NewReader(data))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&signed);err!=nil{return SignedManifest{},err}
 var extra any
 if err:=decoder.Decode(&extra);err!=io.EOF {
  if err==nil{return SignedManifest{},errors.New("trailing backup manifest JSON")}
  return SignedManifest{},err
 }
 if err:=ValidateManifest(signed.Manifest);err!=nil{return SignedManifest{},err}
 return signed,nil
}
