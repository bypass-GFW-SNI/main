package main

import (
	"bufio"
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
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	Version = "1.2"
)

var (
	// dns setting correspond to the above
	dnsCli = sync.Pool{}

	proxyAddr   map[string]struct{} // no async r & w so ok
	resolvLock  sync.Map
	cacheCert   sync.Map
	cacheResolv sync.Map

	caParent *x509.Certificate
	caPriKey *rsa.PrivateKey

	listenAddr = kingpin.Flag("address", "Network address to listen on.").
		Short('i').Default("localhost").Strings()
	caCert = kingpin.Flag("cert", "CA cert file.").
		Short('c').Required().String()
	caKey = kingpin.Flag("key", "CA private key file.").
		Short('k').Required().String()
	defDNS = kingpin.Flag("def-dns", "Upstream default DNS.").
		Default("223.5.5.5:53").String()
	defDNSNet = kingpin.Flag("def-dns-net", "Upstream default DNS network type.").
		Default("udp").Enum("udp", "tcp", "tcp-tls")
	gfwDNS = kingpin.Flag("gfw-dns", "Upstream non-polluted DNS.").
		Default("1.0.0.1:853").String()
	gfwDNSNet = kingpin.Flag("gfw-dns-net", "Upstream non-polluted DNS network type.").
		Default("tcp-tls").Enum("udp", "tcp", "tcp-tls")
	certExpire = kingpin.Flag("cert-expire", "Cert expire time.").
		Default("2000h").Duration()
	dialTimeout = kingpin.Flag("dial-timeout", "Dialing timeout limit.").
		Default("5s").Duration()
	pollInterval = kingpin.Flag("poll-interval", "File change detection interval. Set to 0 to disable.").
		Default("2s").Duration()
	logLevel = kingpin.Flag("log", "Log level.").
		Short('v').Default("info").Enum("panic", "fatal", "error", "warn", "info", "debug")
	proxyList = kingpin.Flag("list", "Proxy list.").
		Short('l').Required().String()
	hostsFile = kingpin.Flag("hosts", "HOSTS file.").
		Default("HOSTS.txt").OpenFile(os.O_RDWR|os.O_CREATE, 0666)
	no53 = kingpin.Flag("no-dns", "Disable DNS server.").Bool()
	no80 = kingpin.Flag("no-http", "Disable listen on HTTP port.").Bool()
)

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

func resolveRealIP(host string) (ret []string) {
	cli := dnsCli.Get().(*dns.Client)
	defer dnsCli.Put(cli)
	cli.Net = *gfwDNSNet

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
	r, _, err := cli.Exchange(q, *gfwDNS)
	if err != nil {
		log.Error(err)
		return
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.AAAA); ok {
			ret = append(ret, net.JoinHostPort(a.AAAA.String(), "443"))
		}
	}

	// ask A (ipv4) address
	q.Question[0].Qtype = dns.TypeA
	r, _, err = cli.Exchange(q, *gfwDNS)
	if err != nil {
		log.Error(err)
		return
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			ret = append(ret, net.JoinHostPort(a.A.String(), "443"))
		}
	}
	return
}

func forwardTls(conn *tls.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debug(err)
		}
	}()

	if err := conn.Handshake(); err != nil {
		log.Debug("handshake error: " + err.Error())
		return
	}
	host := conn.ConnectionState().ServerName
	if !needsProxy(host) {
		log.Errorf("%s needs no proxy", host)
		return
	}
	log.Debug(host)

	d := &net.Dialer{Timeout: *dialTimeout}
	config := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// bypass tls verification and manually do it
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				cert, _ := x509.ParseCertificate(asn1Data)
				certs[i] = cert
			}
			opts := x509.VerifyOptions{
				DNSName:       host,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			return err
		},
	}

	var i net.Conn
	var err error
	lock := new(sync.Mutex)
	actualL, _ := resolvLock.LoadOrStore(host, lock) // one resolve at a time
	lock = actualL.(*sync.Mutex)
	lock.Lock()

	if r, ok := cacheResolv.Load(host); ok {
		i, err = tls.DialWithDialer(d, "tcp", r.(string), config)
		if err != nil {
			log.WithError(err).Debug("dialing cached addr error")
		}
	} else {
		err = errors.New("no cached addr")
	}

	if err != nil {
		addrs := resolveRealIP(host)
		if addrs == nil {
			log.Warnf("%s resolve error", host)
			lock.Unlock()
			return
		}
		for _, addr := range addrs {
			i, err = tls.DialWithDialer(d, "tcp", addr, config)
			if err == nil {
				cacheResolv.Store(host, addr)
				break
			}
		}
		if err != nil {
			log.WithField("err", err).Warnf("Cannot access %s", host)
			lock.Unlock()
			return
		}
	}
	lock.Unlock()
	defer func() {
		if err := i.Close(); err != nil {
			log.Debug(err)
		}
	}()

	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(i, conn)
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, i)
		finished <- struct{}{}
	}()
	<-finished
}

func forwardDns(addr net.IP) dns.HandlerFunc {
	actualType := dns.TypeA
	if addr.To4() == nil {
		actualType = dns.TypeAAAA
	}
	return func(w dns.ResponseWriter, m *dns.Msg) {
		if len(m.Question) > 1 { // is multiple-question query valid?
			log.WithField("len", len(m.Question)).Warn("too many questions")
		}

		if m.Question[0].Qtype == dns.TypeA || m.Question[0].Qtype == dns.TypeAAAA {
			domain := m.Question[0].Name
			if needsProxy(domain[:len(domain)-1]) {
				msg := new(dns.Msg)
				msg.SetReply(m)
				msg.Authoritative = true
				hdr := dns.RR_Header{
					Name:   domain,
					Rrtype: actualType,
					Class:  dns.ClassINET,
					Ttl:    60,
				}
				switch actualType {
				case dns.TypeA:
					msg.Answer = []dns.RR{
						&dns.A{
							Hdr: hdr,
							A:   addr,
						},
					}
				case dns.TypeAAAA:
					msg.Answer = []dns.RR{
						&dns.AAAA{
							Hdr:  hdr,
							AAAA: addr,
						},
					}
				}
				if err := w.WriteMsg(msg); err != nil {
					log.Error(err)
				}
				return
			}
		}

		cli := dnsCli.Get().(*dns.Client)
		defer dnsCli.Put(cli)
		cli.Net = *defDNSNet

		r, _, err := cli.Exchange(m, *defDNS)
		if err != nil {
			log.Error(err)
			return
		}
		if err := w.WriteMsg(r); err != nil {
			log.Error(err)
		}
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
		NotAfter:  time.Now().Add(*certExpire),

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
	fil, err := os.Open(*proxyList)
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
	initStat, err := os.Stat(*proxyList)
	if err != nil {
		log.Fatal(err)
	}
	updateConfig()

	go func() {
		for {
			time.Sleep(*pollInterval)

			stat, err := os.Stat(*proxyList)
			if err != nil {
				log.Error(err)
				continue
			}

			if stat.Size() != initStat.Size() || stat.ModTime() != initStat.ModTime() {
				log.Info("conf file changed")
				updateConfig()
				initStat = stat
			}
		}
	}()
}

func saveCacheResolvAddr() {
	log.Print("Saving address mapping...")
	if _, err := (*hostsFile).Seek(0, io.SeekStart); err != nil {
		log.Panic(err)
	}
	if err := (*hostsFile).Truncate(0); err != nil {
		log.Panic(err)
	}
	defer (*hostsFile).Close()

	cacheResolv.Range(func(key, value interface{}) bool {
		host, _, err := net.SplitHostPort(value.(string))
		if err != nil {
			host = value.(string)
		}
		_, _ = (*hostsFile).WriteString(host)
		_, _ = (*hostsFile).Write([]byte{'\t'})
		_, _ = (*hostsFile).WriteString(key.(string))
		_, _ = (*hostsFile).Write([]byte{'\n'})
		return true
	})
}

func loadCacheResolvAddr() {
	scanner := bufio.NewScanner(*hostsFile)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		split := strings.Fields(text)
		cacheResolv.Store(split[1], net.JoinHostPort(split[0], "443"))
	}
}

func init() {
	kingpin.Version(Version)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	dnsCli.New = func() interface{} {
		return &dns.Client{Timeout: *dialTimeout}
	}
	loadCacheResolvAddr()

	level, _ := log.ParseLevel(*logLevel)
	log.SetLevel(level)

	// read ca cert
	certPEMBlock, err := ioutil.ReadFile(*caCert)
	if err != nil {
		log.Fatal(err)
	}
	certDERBlock, _ := pem.Decode(certPEMBlock)
	caParent, err = x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	keyPEMBlock, err := ioutil.ReadFile(*caKey)
	if err != nil {
		log.Fatal(err)
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	caPriKey, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
}

func listen(addr net.IP) {
	s := addr.String()

	// UDP port 53: listen to DNS queries
	if !*no53 {
		go func() {
			log.Fatal(dns.ListenAndServe(net.JoinHostPort(s, "53"), "udp", forwardDns(addr)))
		}()
	}

	// TCP port 80: listen to HTTP port to avoid redirection
	if !*no80 {
		go func() {
			log.Fatal(http.ListenAndServe(net.JoinHostPort(s, "80"), http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, r.Host+" accessed with http", http.StatusForbidden)
				}),
			))
		}()
	}

	log.Infof("Listening on %s...", s)

	list, err := tls.Listen("tcp", net.JoinHostPort(s, "443"), &tls.Config{
		GetCertificate: getCertificate,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := list.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	for {
		conn, err := list.Accept()
		if err != nil {
			log.Error(err)
			continue
		}
		go forwardTls(conn.(*tls.Conn))
	}
}

func main() {
	if *pollInterval != 0 {
		pollingFileChange()
	}

	for _, addr := range *listenAddr {
		parsedIP := net.ParseIP(addr)
		if parsedIP != nil {
			go listen(parsedIP)
		} else {
			ips, e := net.LookupIP(addr)
			if e != nil {
				log.Fatal(e)
			}
			for _, i := range ips {
				go listen(i)
			}
		}
	}

	sigs := make(chan os.Signal, 1)
	done := make(chan struct{}, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		saveCacheResolvAddr()
		done <- struct{}{}
	}()
	<-done
}
