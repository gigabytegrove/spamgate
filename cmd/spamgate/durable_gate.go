package main

import (
 "errors"

 "github.com/gigabytegrove/spamgate/internal/transport"
)

// The SMTP intake must never acknowledge ownership of a message unless
// its complete envelope and RFC822 bytes can be durably spooled first.
// This gate executes before opening any HTTP/SMTP/Milter listeners.
func requireDurableSMTP(inbound *transport.SMTP, queue *transport.DeliveryQueue) error {
 if inbound != nil && (queue == nil || inbound.Queue != queue) {
  return errors.New("SMTP content-filter listener requires a durable delivery queue; remove SPAMGATE_DURABLE_QUEUE=false or disable SPAMGATE_SMTP_LISTEN (Milter-only mode is unaffected)")
 }
 return nil
}
