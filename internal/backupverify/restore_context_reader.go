package backupverify

import (
 "context"
 "io"
)

// restoreContextReader checks cancellation between reads. It does not
// interrupt a filesystem read already blocked in the kernel.
type restoreContextReader struct {
 ctx context.Context
 reader io.Reader
}

func (r *restoreContextReader) Read(p []byte) (int, error) {
 if err := r.ctx.Err(); err != nil { return 0, err }
 n, err := r.reader.Read(p)
 if cancelErr := r.ctx.Err(); cancelErr != nil { return n, cancelErr }
 return n, err
}
