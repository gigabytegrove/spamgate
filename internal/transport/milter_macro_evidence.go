package transport

import (
	"bytes"
	"errors"
	"strings"
)

// milterQueueIDEvidence distinguishes "no queue ID was supplied" from
// "queue-ID evidence was supplied but was malformed". The latter must poison
// an active SMTP transaction rather than silently preserving an earlier ID.
// Empty {i} values are normal before Postfix allocates a queue ID and do not
// erase an already observed, nonempty identity.
func milterQueueIDEvidence(data []byte) (id string, claimed bool, err error) {
	if len(data) == 1 {
		// A macro stage with no definitions is not a queue-ID claim.
		return "", false, nil
	}
	if len(data) < 3 || data[len(data)-1] != 0 {
		return "", false, errors.New("unterminated milter macro definition")
	}
	parts := bytes.Split(data[1:len(data)-1], []byte{0})
	if len(parts)%2 != 0 || len(parts) > 256 {
		return "", false, errors.New("incomplete or excessive milter macro definitions")
	}
	for i := 0; i < len(parts); i += 2 {
		name := string(parts[i])
		if name != "i" && name != "{i}" {
			// Do not treat malformed brace aliases as unrelated macros.
			// A valid unrelated name such as {if_addr} remains untouched.
			if strings.Trim(name, "{}") == "i" {
				return "", true, errors.New("malformed queue-ID macro alias")
			}
			continue
		}
		if claimed {
			return "", true, errors.New("duplicate queue-ID macro")
		}
		claimed = true
		value := parts[i+1]
		if len(value) == 0 {
			continue
		}
		if len(value) > 32 {
			return "", true, errors.New("oversized queue-ID macro")
		}
		for _, b := range value {
			if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
				return "", true, errors.New("invalid queue-ID macro byte")
			}
		}
		id = string(value)
	}
	return id, claimed, nil
}
