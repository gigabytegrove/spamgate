package transport

import (
    "errors"
    "net/smtp"
    "strings"
)

// requireRelayPlainAuth prevents transmitting credentials to a TLS peer that
// does not explicitly advertise the PLAIN SASL mechanism. net/smtp.Client.Auth
// does not itself enforce the EHLO AUTH mechanism list. This check runs only
// after TLS negotiation, so plaintext EHLO advertisements are never trusted.
func requireRelayPlainAuth(client *smtp.Client) error {
    if client == nil {
        return errors.New("SMTP relay client is nil")
    }
    ok, advertised := client.Extension("AUTH")
    if !ok {
        return errors.New("SMTP relay does not advertise AUTH")
    }
    for _, mechanism := range strings.Fields(advertised) {
        if strings.EqualFold(mechanism, "PLAIN") {
            return nil
        }
    }
    return errors.New("SMTP relay does not advertise AUTH PLAIN")
}
