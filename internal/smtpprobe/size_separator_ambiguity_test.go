package smtpprobe

import "testing"

func TestSizeEvidenceMalformedSeparatorCannotBeOverridden(t *testing.T) {
	for _, separator := range []string{":", ";", ",", "/", "+", "-"} {
		for _, reverse := range []bool{false, true} {
			name := "SIZE" + separator + "100"
			lines := []string{"smtp.example", name, "SIZE 200"}
			if reverse {
				lines[1], lines[2] = lines[2], lines[1]
			}
			t.Run(name+map[bool]string{true: "_after", false: "_before"}[reverse], func(t *testing.T) {
				advertised, known, limit, warning := sizeEvidence(lines)
				if !advertised || known || limit != 0 || warning != "DUPLICATE_SIZE_ADVERTISEMENT" {
					t.Fatalf("sizeEvidence(%q) = (%t,%t,%d,%q)", lines, advertised, known, limit, warning)
				}
			})
		}
	}
}

func TestSizeEvidenceMalformedSeparatorAlone(t *testing.T) {
	for _, line := range []string{"SIZE:100", "size;100", "SIZE/100", "SIZE+100", "SIZE-100"} {
		advertised, known, limit, warning := sizeEvidence([]string{"smtp.example", line})
		if !advertised || known || limit != 0 || warning != "MALFORMED_SIZE_ADVERTISEMENT" {
			t.Errorf("%q: got (%t,%t,%d,%q)", line, advertised, known, limit, warning)
		}
	}
}

func TestSizeEvidenceDoesNotConfuseOtherExtensionsOrIdentity(t *testing.T) {
	for _, line := range []string{"SIZEX:100", "SIZES=100", "SIZE2=100", "SIZE_EXTRA=100"} {
		advertised, known, limit, warning := sizeEvidence([]string{"smtp.example", line})
		if advertised || known || limit != 0 || warning != "" {
			t.Errorf("%q: got (%t,%t,%d,%q)", line, advertised, known, limit, warning)
		}
	}
	advertised, known, limit, warning := sizeEvidence([]string{"SIZE:100", "SIZE 200"})
	if !advertised || !known || limit != 200 || warning != "" {
		t.Fatalf("EHLO identity misclassified: (%t,%t,%d,%q)", advertised, known, limit, warning)
	}
}
