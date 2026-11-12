package smtpprobe

import "testing"

func TestCapabilityEvidenceFindingsScopeAndTrust(t *testing.T) {
	cases := []struct {
		name string
		r Result
		want []string
	}{
		{"no EHLO", Result{EHLOCode:550, EHLOWarnings:[]string{"BAD"}, SizeWarning:"BAD"}, nil},
		{"initial malformed", Result{EHLOCode:250, EHLOWarnings:[]string{"BAD"}, SizeWarning:"BAD", SizeAdvertised:true, SizeLimitKnown:true}, []string{"SMTP_EHLO_CAPABILITY_ANOMALY","SMTP_SIZE_LIMIT_UNTRUSTWORTHY"}},
		{"unspecified size", Result{EHLOCode:250, SizeAdvertised:true}, []string{"SMTP_SIZE_LIMIT_UNSPECIFIED"}},
		{"known size", Result{EHLOCode:250, SizeAdvertised:true, SizeLimitKnown:true, SizeLimitBytes:0}, nil},
		{"post TLS unverified", Result{EHLOCode:250, PostTLSEHLOCode:250, PostTLSSizeWarning:"BAD"}, nil},
		{"post TLS EHLO rejected", Result{EHLOCode:250, StartTLSVerified:true, PostTLSEHLOCode:550, PostTLSSizeWarning:"BAD"}, nil},
		{"post TLS malformed", Result{EHLOCode:250, StartTLSVerified:true, PostTLSEHLOCode:250, PostTLSEHLOWarnings:[]string{"BAD"}, PostTLSSizeWarning:"BAD"}, []string{"SMTP_EHLO_CAPABILITY_ANOMALY","SMTP_SIZE_LIMIT_UNTRUSTWORTHY"}},
	}
	for _,tc := range cases {
		t.Run(tc.name,func(t *testing.T) {
			got := findingCodes(Assess(tc.r))
			for _,code := range tc.want {
				if !got[code] { t.Errorf("missing %s in %+v",code,got) }
			}
			for _,code := range []string{"SMTP_EHLO_CAPABILITY_ANOMALY","SMTP_SIZE_LIMIT_UNTRUSTWORTHY","SMTP_SIZE_LIMIT_UNSPECIFIED"} {
				want := false
				for _,w := range tc.want { if w==code { want=true } }
				if got[code]!=want {t.Errorf("%s got=%v want=%v",code,got[code],want)}
			}
		})
	}
}

func TestCapabilityEvidenceFindingsNeverEchoPeerText(t *testing.T) {
	r:=Result{EHLOCode:250, EHLOWarnings:[]string{"SECRET-SERVER-TEXT"}, SizeWarning:"SECRET-SERVER-TEXT"}
	for _,f:=range Assess(r) {
		if containsPeerText(f.Message) {t.Fatalf("untrusted peer text leaked: %+v",f)}
	}
}
func containsPeerText(s string) bool {
	return len(s)>=18 && findSubstring(s,"SECRET-SERVER-TEXT")
}
func findSubstring(s, needle string) bool {
	for i:=0;i+len(needle)<=len(s);i++ {if s[i:i+len(needle)]==needle{return true}}
	return false
}
