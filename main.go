package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

const (
	// certs
	caCert = "CA.crt"
	caKey  = "CA.key"
	// dns
	defDNS = "114.114.114.114:53"
	gfwDNS = "1.1.1.1:853"
	// time
	certExpire   = time.Hour * 24 * 30 // a month
	dialTimeout  = 3 * time.Second
	pollInterval = time.Second
	// misc
	logLevel   = log.DebugLevel
	configFile = "domain.conf"
)

var (
	// dns setting correspond to the above
	defDnsCli = sync.Pool{New: func() interface{} {
		return &dns.Client{Net: "udp"}
	}}
	gfwDnsCli = sync.Pool{New: func() interface{} {
		return &dns.Client{Net: "tcp-tls"}
	}}

	proxyAddr   map[string]struct{} // no async r & w so ok
	cacheCert   sync.Map
	cacheResolv sync.Map

	caParent *x509.Certificate
	caPriKey *rsa.PrivateKey
)

type Resolv struct {
	addr   string
	expire time.Time
}

func (r *Resolv) Expired() bool {
	return r.expire.Before(time.Now())
}

// Utils
func copyHeaders(dst, src http.Header) {
	for k := range dst {
		dst.Del(k)
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func needsProxy(domain string) bool {
	if _, ok := proxyAddr[domain]; ok {
		return true
	}
	secondary, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Errorf("hostname invalid: %s", domain)
		return false
	}
	for domain != secondary {
		dot := strings.IndexByte(domain, '.')
		domain = domain[dot+1:]
		if _, ok := proxyAddr[domain]; ok {
			return true
		}
	}
	return false
}

func resolveRealIP(ctx context.Context, host string) (ret []*Resolv) {
	cli := gfwDnsCli.Get().(*dns.Client)
	defer gfwDnsCli.Put(cli)

	// ask AAAA (ipv6) address first
	q := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(host),
				Qtype:  dns.TypeAAAA,
				Qclass: dns.ClassINET,
			},
		},
	}
	r, _, err := cli.ExchangeContext(ctx, q, gfwDNS)
	if err != nil {
		log.Debug(err)
		return
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.AAAA); ok {
			ret = append(ret, &Resolv{
				addr:   net.JoinHostPort(a.AAAA.String(), "443"),
				expire: time.Now().Add(time.Duration(a.Hdr.Ttl) * time.Second),
			})
		}
	}

	// ask A (ipv4) address
	q.Question[0].Qtype = dns.TypeA
	r, _, err = cli.ExchangeContext(ctx, q, gfwDNS)
	if err != nil {
		log.Debug(err)
		return
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			ret = append(ret, &Resolv{
				addr:   net.JoinHostPort(a.A.String(), "443"),
				expire: time.Now().Add(time.Duration(a.Hdr.Ttl) * time.Second),
			})
		}
	}
	return
}

func forwardHttps(w http.ResponseWriter, r *http.Request) {
	if !needsProxy(r.Host) {
		http.Error(w, r.Host+" need no proxy", http.StatusBadRequest)
		return
	}
	r.URL.Scheme = "https"
	r.URL.Host = r.Host
	log.Debug(r.URL.String())

	var trans http.Transport
	trans.DialContext = func(ctx context.Context, network, _ string) (i net.Conn, e error) {
		var serName string
		d := net.Dialer{Timeout: dialTimeout}
		if r, ok := cacheResolv.Load(r.Host); ok && !r.(*Resolv).Expired() {
			serName = r.(*Resolv).addr
			i, e = d.DialContext(ctx, network, serName)
		} else {
			e = errors.New("no cached addr")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if e != nil {
			addrs := resolveRealIP(ctx, r.Host)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if addrs == nil {
				http.Error(w, r.Host+" resolve error", http.StatusBadGateway)
				return
			}
			for _, addr := range addrs {
				i, e = d.DialContext(ctx, network, addr.addr)
				if e == nil {
					serName = addr.addr
					cacheResolv.Store(r.Host, addr)
					break
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			if e != nil {
				http.Error(w, r.Host+" is IP-blocked", http.StatusBadGateway)
				return
			}
		}
		trans.TLSClientConfig = &tls.Config{
			ServerName:         serName,
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				// bypass tls verification and manually do it
				certs := make([]*x509.Certificate, len(rawCerts))
				for i, asn1Data := range rawCerts {
					cert, _ := x509.ParseCertificate(asn1Data)
					certs[i] = cert
				}
				opts := x509.VerifyOptions{
					DNSName:       r.Host,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range certs[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := certs[0].Verify(opts)
				if err != nil {
					if ctx.Err() == nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
					}
				}
				return err
			},
		}
		return
	}
	resp, err := trans.RoundTrip(r)
	if err != nil {
		log.Debug(err)
		return
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error(err)
		}
	}()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Debug(err)
	}
}

func forwardDns(w dns.ResponseWriter, m *dns.Msg) {
	if len(m.Question) > 1 { // is multiple-question query valid?
		log.WithField("len", len(m.Question)).Fatal("too many questions")
	}

	if m.Question[0].Qtype == dns.TypeA || m.Question[0].Qtype == dns.TypeAAAA {
		domain := m.Question[0].Name
		if needsProxy(domain[:len(domain)-1]) {
			msg := new(dns.Msg)
			msg.SetReply(m)
			msg.Authoritative = true
			hdr := dns.RR_Header{
				Name:   domain,
				Rrtype: m.Question[0].Qtype,
				Class:  dns.ClassINET,
				Ttl:    60,
			}
			switch m.Question[0].Qtype {
			case dns.TypeA:
				msg.Answer = []dns.RR{
					&dns.A{
						Hdr: hdr,
						A:   net.IPv4(127, 0, 0, 1),
					},
				}
			case dns.TypeAAAA:
				msg.Answer = []dns.RR{
					&dns.AAAA{
						Hdr:  hdr,
						AAAA: net.IPv6loopback,
					},
				}
			}
			if err := w.WriteMsg(msg); err != nil {
				log.Error(err)
			}
			return
		}
	}

	cli := defDnsCli.Get().(*dns.Client)
	defer defDnsCli.Put(cli)

	r, _, err := cli.Exchange(m, defDNS)
	if err != nil {
		log.Debug(err)
		return
	}
	if err := w.WriteMsg(r); err != nil {
		log.Error(err)
	}
}

func getCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if info.ServerName == "" {
		return nil, errors.New("no SNI info")
	}

	if cert, ok := cacheCert.Load(info.ServerName); ok {
		return cert.(*tls.Certificate), nil
	}

	secondary, err := publicsuffix.EffectiveTLDPlusOne(info.ServerName)
	if err != nil {
		log.Errorf("invalid hostname: %s", secondary)
		return nil, err
	}

	var cn string
	if info.ServerName == secondary {
		cn = secondary
	} else {
		dot := strings.IndexByte(info.ServerName, '.')
		cn = info.ServerName[dot+1:]
	}

	if cert, ok := cacheCert.Load(cn); ok {
		return cert.(*tls.Certificate), nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Errorf("failed to generate private key: %s", err)
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Errorf("failed to generate serial number: %s", err)
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
			Country:    []string{"CN"},
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certExpire),

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"*." + cn, cn},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caParent, priv.Public(), caPriKey)
	if err != nil {
		log.Errorf("failed to create certificate: %s", err)
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	cacheCert.Store(cn, cert)
	return cert, nil
}

func updateConfig() {
	fil, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := fil.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	scanner := bufio.NewScanner(fil)

	newMap := make(map[string]struct{})
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			newMap[text] = struct{}{}
		}
	}
	proxyAddr = newMap
}

func pollingFileChange() { // only polling works due to different behaviors of editors
	initStat, err := os.Stat(configFile)
	if err != nil {
		log.Fatal(err)
	}
	updateConfig()

	go func() {
		for {
			time.Sleep(pollInterval)

			stat, err := os.Stat(configFile)
			if err != nil {
				log.Fatal(err)
			}

			if stat.Size() != initStat.Size() || stat.ModTime() != initStat.ModTime() {
				log.Info("conf file changed")
				updateConfig()
				initStat = stat
			}
		}
	}()
}

func init() {
	log.SetLevel(logLevel)

	// read ca cert
	certPEMBlock, err := ioutil.ReadFile(caCert)
	if err != nil {
		log.Fatal(err)
	}
	certDERBlock, _ := pem.Decode(certPEMBlock)
	caParent, err = x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	keyPEMBlock, err := ioutil.ReadFile(caKey)
	if err != nil {
		log.Fatal(err)
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	caPriKey, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	pollingFileChange()

	// UDP port 53: listen to DNS queries
	go func() {
		log.Fatal(dns.ListenAndServe("localhost:53", "udp", dns.HandlerFunc(forwardDns)))
	}()

	// TCP port 80: listen to HTTP port to avoid redirection
	go func() {
		log.Fatal(http.ListenAndServe("localhost:80", http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, r.Host+" accessed with http", http.StatusForbidden)
			}),
		))
	}()

	server := &http.Server{Handler: http.HandlerFunc(forwardHttps)}
	list, err := tls.Listen("tcp", "localhost:443", &tls.Config{
		GetCertificate: getCertificate,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.Serve(list))
}
