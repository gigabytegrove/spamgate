package core

// DNS RCODE support for RFC 9989 np= policy. LookupIPAddr cannot distinguish
// NXDOMAIN from NODATA. This is an explicit opt-in for the default resolver.
import (
 "context"
 "crypto/rand"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "strings"
 "time"
)

const (
 dmarcDNSMaxConfig = 65536
 dmarcDNSMaxTCPResponse = 4096
 dmarcDNSMaxServers = 3
 dmarcDNSQueryTimeout = time.Second
)

type defaultDMARCResolver struct { SPFResolver }

// Never mix an injected/custom resolver with the host's system DNS view.
func dmarcPolicyResolver(resolver SPFResolver) SPFResolver {
 if resolver == nil { resolver = net.DefaultResolver }
 if r, ok := resolver.(*net.Resolver); ok && r == net.DefaultResolver && os.Getenv("SPAMGATE_DMARC_NP_DNS") == "system" {
  return defaultDMARCResolver{SPFResolver: resolver}
 }
 return resolver
}

func (r defaultDMARCResolver) DMARCNameNXDOMAIN(ctx context.Context, domain string) (bool, error) {
 return dmarcDNSClient{configPath: "/etc/resolv.conf"}.nameNXDOMAIN(ctx, domain)
}

type dmarcDNSClient struct {
 configPath string
 serversOverride []string // loopback integration fixtures
}

func (c dmarcDNSClient) servers() ([]string, error) {
 f, err := os.Open(c.configPath)
 if err != nil { return nil, fmt.Errorf("read system DNS configuration: %w", err) }
 defer f.Close()
 b, err := io.ReadAll(io.LimitReader(f, dmarcDNSMaxConfig+1))
 if err != nil { return nil, err }
 if len(b) > dmarcDNSMaxConfig { return nil, errors.New("system DNS configuration exceeds limit") }
 var servers []string
 for _, line := range strings.Split(string(b), "
") {
  line, _, _ = strings.Cut(line, "#")
  fields := strings.Fields(line)
  if len(fields) == 0 || fields[0] != "nameserver" { continue }
  if len(fields) != 2 { return nil, errors.New("invalid nameserver configuration") }
  ip := net.ParseIP(fields[1])
  if ip == nil { return nil, errors.New("non-IP system DNS nameserver") }
  if len(servers) < dmarcDNSMaxServers { servers = append(servers, net.JoinHostPort(ip.String(), "53")) }
 }
 if len(servers) == 0 { return nil, errors.New("no system DNS nameservers configured") }
 return servers, nil
}

func dmarcDNSQuestion(domain string) ([]byte, error) {
 if !spfValidDomain(domain) { return nil, errors.New("invalid DNS Author Domain") }
 domain = strings.ToLower(strings.TrimSuffix(domain, "."))
 var q []byte
 for _, label := range strings.Split(domain, ".") {
  if len(label) == 0 || len(label) > 63 { return nil, errors.New("invalid DNS label length") }
  q = append(q, byte(len(label)))
  q = append(q, label...)
 }
 q = append(q, 0, 0, 1, 0, 1) // root, A, IN
 if len(q) > 255+4 { return nil, errors.New("DNS question too long") }
 return q, nil
}

// Bounded compression pointer decoding, returning the original-stream offset.
func dmarcDNSDecodeName(msg []byte, start int) (string, int, error) {
 pos, end, jumps := start, -1, 0
 var labels []string
 for {
  if pos >= len(msg) { return "", 0, errors.New("truncated DNS name") }
  size := int(msg[pos])
  if size&0xc0 == 0xc0 {
   if pos+1 >= len(msg) { return "", 0, errors.New("truncated DNS pointer") }
   target := (size&0x3f)<<8 | int(msg[pos+1])
   if end < 0 { end = pos+2 }
   if target >= len(msg) || target >= pos || jumps >= 16 { return "", 0, errors.New("invalid DNS compression pointer") }
   pos, jumps = target, jumps+1
   continue
  }
  if size&0xc0 != 0 || size > 63 { return "", 0, errors.New("invalid DNS label") }
  pos++
  if size == 0 {
   if end < 0 { end = pos }
   return strings.Join(labels, "."), end, nil
  }
  if pos+size > len(msg) { return "", 0, errors.New("truncated DNS label") }
  labels = append(labels, strings.ToLower(string(msg[pos:pos+size])))
  if len(labels) > 127 { return "", 0, errors.New("DNS name too deep") }
  pos += size
 }
}

func dmarcDNSRCODE(msg []byte, id uint16, domain string) (int, bool, error) {
 if len(msg) < 12 { return 0, false, errors.New("short DNS response") }
 if binary.BigEndian.Uint16(msg[:2]) != id { return 0, false, errors.New("DNS transaction ID mismatch") }
 flags := binary.BigEndian.Uint16(msg[2:4])
 if flags&0x8000 == 0 || flags&0x7800 != 0 { return 0, false, errors.New("not a standard DNS response") }
 if flags&0x0200 != 0 { return 0, true, nil } // validate complete question on TCP retry
 if binary.BigEndian.Uint16(msg[4:6]) != 1 { return 0, false, errors.New("unexpected DNS question count") }
 name, offset, err := dmarcDNSDecodeName(msg, 12)
 if err != nil { return 0, false, err }
 if name != strings.ToLower(strings.TrimSuffix(domain, ".")) || offset+4 > len(msg) ||
  binary.BigEndian.Uint16(msg[offset:offset+2]) != 1 || binary.BigEndian.Uint16(msg[offset+2:offset+4]) != 1 {
  return 0, false, errors.New("DNS response question mismatch")
 }
 rcode := int(flags & 0x000f)
 if rcode == 3 && binary.BigEndian.Uint16(msg[6:8]) != 0 {
  // An existing CNAME may point to an NXDOMAIN target.
  return 0, false, errors.New("NXDOMAIN response contains answer records; Author Domain existence ambiguous")
 }
 return rcode, false, nil
}

func dmarcDNSDeadline(ctx context.Context) time.Time {
 end := time.Now().Add(dmarcDNSQueryTimeout)
 if deadline, ok := ctx.Deadline(); ok && deadline.Before(end) { end = deadline }
 return end
}

func dmarcDNSExchange(ctx context.Context, server string, packet []byte, tcp bool) ([]byte, error) {
 network := "udp"
 if tcp { network = "tcp" }
 conn, err := (&net.Dialer{}).DialContext(ctx, network, server)
 if err != nil { return nil, err }
 defer conn.Close()
 if err = conn.SetDeadline(dmarcDNSDeadline(ctx)); err != nil { return nil, err }
 if tcp {
  if len(packet) > 65535 { return nil, errors.New("DNS request too large") }
  prefix := []byte{byte(len(packet)>>8), byte(len(packet))}
  if _, err = conn.Write(append(prefix, packet...)); err != nil { return nil, err }
  var size [2]byte
  if _, err = io.ReadFull(conn, size[:]); err != nil { return nil, err }
  n := int(binary.BigEndian.Uint16(size[:]))
  if n < 12 || n > dmarcDNSMaxTCPResponse { return nil, errors.New("DNS TCP response outside size limits") }
  reply := make([]byte, n)
  _, err = io.ReadFull(conn, reply)
  return reply, err
 }
 if _, err = conn.Write(packet); err != nil { return nil, err }
 reply := make([]byte, 512)
 n, err := conn.Read(reply)
 if err != nil { return nil, err }
 return reply[:n], nil
}

func (c dmarcDNSClient) nameNXDOMAIN(ctx context.Context, domain string) (bool, error) {
 if err := ctx.Err(); err != nil { return false, err }
 question, err := dmarcDNSQuestion(domain)
 if err != nil { return false, err }
 servers := c.serversOverride
 if len(servers) == 0 {
  servers, err = c.servers()
  if err != nil { return false, err }
 }
 var idBytes [2]byte
 if _, err := rand.Read(idBytes[:]); err != nil { return false, err }
 id := binary.BigEndian.Uint16(idBytes[:])
 packet := make([]byte, 12, 12+len(question))
 binary.BigEndian.PutUint16(packet[:2], id)
 binary.BigEndian.PutUint16(packet[2:4], 0x0100)
 binary.BigEndian.PutUint16(packet[4:6], 1)
 packet = append(packet, question...)
 var lastErr error
 for _, server := range servers {
  if err := ctx.Err(); err != nil { return false, err }
  reply, err := dmarcDNSExchange(ctx, server, packet, false)
  if err == nil {
   var rcode int
   var truncated bool
   rcode, truncated, err = dmarcDNSRCODE(reply, id, domain)
   if err == nil && truncated {
    reply, err = dmarcDNSExchange(ctx, server, packet, true)
    if err == nil {
     rcode, truncated, err = dmarcDNSRCODE(reply, id, domain)
     if err == nil && truncated { err = errors.New("truncated DNS TCP response") }
    }
   }
   if err == nil {
    switch rcode {
    case 0: return false, nil // NOERROR, including NODATA
    case 3: return true, nil  // NXDOMAIN, no alias answer
    default: err = fmt.Errorf("DNS server returned RCODE %d", rcode)
    }
   }
  }
  lastErr = err
 }
 return false, fmt.Errorf("Author Domain DNS status unresolved: %w", lastErr)
}
