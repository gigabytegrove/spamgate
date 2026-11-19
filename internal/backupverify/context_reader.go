package backupverify

import (
 "context"
 "errors"
 "io"
)

// verificationContextReader checks cancellation on every streaming read.
// A kernel-blocked Read cannot be interrupted, but no further reads are
// initiated after cancellation.
type verificationContextReader struct {
 ctx context.Context
 reader io.Reader
}

func (r *verificationContextReader) Read(p []byte) (int, error) {
 if r.ctx == nil { return 0, errors.New("verification context required") }
 if err := r.ctx.Err(); err != nil { return 0, err }
 n, err := r.reader.Read(p)
 if cancelErr := r.ctx.Err(); cancelErr != nil { return n, cancelErr }
 return n, err
}
