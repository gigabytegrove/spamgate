package transport

import "testing"

func TestRspamdRequestPreflight(t *testing.T) {
 tests := []struct{
  name, helo, compression, encoding, wantHelo string
  reject bool
 }{
  {"absent", "", "", "", "", false},
  {"valid DNS", "mail.example.test", "", "", "mail.example.test", false},
  {"valid IPv4 literal", "[192.0.2.1]", "", "", "[192.0.2.1]", false},
  {"valid IPv6 literal", "[IPv6:2001:db8::1]", "", "", "[IPv6:2001:db8::1]", false},
  {"unavailable", "[UNAVAILABLE]", "", "", "", false},
  {"temporary unavailable", "[TEMPUNAVAIL]", "", "", "", false},
  {"invalid DNS", "bad..example.test", "", "", "", true},
  {"invalid bracket", "[192.0.2.1", "", "", "", true},
  {"invalid unicode", "máil.example.test", "", "", "", true},
  {"invalid whitespace", " mail.example.test", "", "", "", true},
  {"unsupported gzip", "", "", "gzip", "", true},
  {"unsupported zstd", "", "", "zstd", "", true},
  {"unsupported br", "", "", "br", "", true},
  {"unsupported chained", "", "", "identity,gzip", "", true},
  {"identity encoding", "", "", "identity", "", false},
  {"case folded identity", "", "", "IDENTITY", "", false},
  {"compression zstd", "", "zstd", "", "", true},
  {"compression none", "", "none", "", "", true},
  {"compression with identity", "", "zstd", "identity", "", true},
 }
 for _, tc := range tests {
  t.Run(tc.name, func(t *testing.T) {
   got, err := rspamdValidateRequestPreflight(rspamdRequestMetadata{
    Helo: tc.helo, Compression: tc.compression, ContentEncoding: tc.encoding,
   })
   if (err != nil) != tc.reject { t.Fatalf("got=%q err=%v reject=%v", got, err, tc.reject) }
   if !tc.reject && got != tc.wantHelo { t.Fatalf("got=%q want=%q", got, tc.wantHelo) }
  })
 }
}
