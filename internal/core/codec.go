package core

import (
	"encoding/base64"
	"io"
	"mime/quotedprintable"
)

func base64Decode(dst, src []byte) (int, error) {
	if len(src)%4 == 0 {
		return base64.StdEncoding.Decode(dst, src)
	}
	return base64.RawStdEncoding.Decode(dst, src)
}
func quotedPrintableReader(r io.Reader) io.Reader { return quotedprintable.NewReader(r) }
