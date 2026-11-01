package core

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// dmarcDNSValidateSections checks that a DNS reply is a complete, unambiguous
// packet before its RCODE can be used to select an actionable DMARC np= policy.
// It does not treat unverified authority data as DNSSEC proof.
func dmarcDNSValidateSections(msg []byte, offset int) error {
	if len(msg) < 12 || offset < 12 || offset > len(msg) {
		return errors.New("invalid DNS section offset")
	}
	counts := [3]int{
		int(binary.BigEndian.Uint16(msg[6:8])),
		int(binary.BigEndian.Uint16(msg[8:10])),
		int(binary.BigEndian.Uint16(msg[10:12])),
	}
	total := counts[0] + counts[1] + counts[2]
	// The shortest resource record is a root name and a ten-byte RR header.
	if total > (len(msg)-offset)/11 {
		return errors.New("DNS record counts exceed response length")
	}
	seenOPT := false
	for section, count := range counts {
		for i := 0; i < count; i++ {
			name, end, err := dmarcDNSDecodeName(msg, offset)
			if err != nil {
				return fmt.Errorf("invalid DNS resource record owner: %w", err)
			}
			if end > len(msg) || len(msg)-end < 10 {
				return errors.New("truncated DNS resource record header")
			}
			kind := binary.BigEndian.Uint16(msg[end : end+2])
			ttl := binary.BigEndian.Uint32(msg[end+4 : end+8])
			dataLen := int(binary.BigEndian.Uint16(msg[end+8 : end+10]))
			offset = end + 10
			if dataLen > len(msg)-offset {
				return errors.New("truncated DNS resource record data")
			}
			if kind == 41 { // EDNS(0) OPT pseudo-record
				if section != 2 || seenOPT || name != "" {
					return errors.New("invalid or duplicate DNS OPT record")
				}
				seenOPT = true
				if ttl>>24 != 0 {
					// The 12-bit full RCODE is not NXDOMAIN when extended bits
					// are nonzero, even if the base four bits equal three.
					return errors.New("DNS extended RCODE is not supported")
				}
				if (ttl>>16)&0xff != 0 {
					return errors.New("unsupported DNS EDNS version")
				}
				// Each EDNS option has a four-byte code/length header.
				// Reject incomplete options rather than trusting a malformed
				// packet to select a DMARC reject/quarantine policy.
				for option := offset; option < offset+dataLen; {
					if offset+dataLen-option < 4 {
						return errors.New("truncated DNS EDNS option header")
					}
					optionLen := int(binary.BigEndian.Uint16(msg[option+2 : option+4]))
					option += 4
					if optionLen > offset+dataLen-option {
						return errors.New("truncated DNS EDNS option data")
					}
					option += optionLen
				}
			}
			offset += dataLen
		}
	}
	if offset != len(msg) {
		return errors.New("unaccounted bytes after DNS response sections")
	}
	return nil
}
