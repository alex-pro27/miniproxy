package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string      `yaml:"listen"`
	Auth   *AuthConfig `yaml:"auth,omitempty"`
}

type AuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ProxyServer struct {
	auth      *AuthConfig
	transport *http.Transport
}

const (
	socksVersion5                = 0x05
	socksAuthNone                = 0x00
	socksAuthUsernamePassword    = 0x02
	socksAuthNoAcceptableMethod  = 0xFF
	socksAuthVersion             = 0x01
	socksCommandConnect          = 0x01
	socksAddressTypeIPv4         = 0x01
	socksAddressTypeDomain       = 0x03
	socksAddressTypeIPv6         = 0x04
	socksReplySucceeded          = 0x00
	socksReplyGeneralFailure     = 0x01
	socksReplyConnectionRefused  = 0x05
	socksReplyCommandUnsupported = 0x07
	socksReplyAddressUnsupported = 0x08
)

func main() {
	configPath := os.Getenv("MINIPROXY_CFG_PATH")
	if configPath == "" {
		log.Fatal("MINIPROXY_CFG_PATH is required")
	}

	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	proxy := &ProxyServer{
		auth: config.Auth,
		transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	server := &http.Server{
		Addr:              config.Listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}

	log.Printf("proxy listening on %s auth=%t", config.Listen, proxy.authEnabled())
	if err := proxy.Serve(listener, server); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server failed: %v", err)
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if config.Listen == "" {
		config.Listen = ":8080"
	}

	if config.Auth != nil {
		if config.Auth.Username == "" && config.Auth.Password == "" {
			config.Auth = nil
		} else if config.Auth.Username == "" || config.Auth.Password == "" {
			return nil, fmt.Errorf("auth.username and auth.password must both be set, or both be empty")
		}
	}

	return &config, nil
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now()
	logger := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	target := requestTarget(r)

	defer func() {
		log.Printf(
			"client=%s method=%s target=%s status=%d duration=%s",
			r.RemoteAddr,
			r.Method,
			target,
			logger.statusCode,
			time.Since(startedAt).Round(time.Millisecond),
		)
	}()

	if !p.authorized(r) {
		logger.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(logger, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(logger, r)
		return
	}

	p.handleHTTP(logger, r)
}

func (p *ProxyServer) Serve(listener net.Listener, server *http.Server) error {
	httpListener := newConnListener(listener.Addr())
	errCh := make(chan error, 2)

	go func() {
		err := server.Serve(httpListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	go func() {
		errCh <- p.routeConnections(listener, httpListener)
	}()

	err := <-errCh
	httpListener.Close()
	_ = server.Close()
	_ = listener.Close()
	otherErr := <-errCh

	if err != nil {
		return err
	}
	return otherErr
}

func (p *ProxyServer) routeConnections(listener net.Listener, httpListener *connListener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		go p.dispatchConn(conn, httpListener)
	}
}

func (p *ProxyServer) dispatchConn(conn net.Conn, httpListener *connListener) {
	buffered := newBufferedConn(conn)
	version, err := buffered.peekByte()
	if err != nil {
		conn.Close()
		return
	}

	if version == socksVersion5 {
		p.handleSOCKS5(buffered)
		return
	}

	if err := httpListener.Deliver(buffered); err != nil {
		conn.Close()
	}
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "proxy request must use absolute URL", http.StatusBadRequest)
		return
	}

	outReq := r.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Proto = "HTTP/1.1"
	outReq.ProtoMajor = 1
	outReq.ProtoMinor = 1
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		log.Printf("upstream request failed target=%s err=%v", requestTarget(r), err)
		http.Error(w, fmt.Sprintf("upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("copy response body: %v", err)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("connect target failed target=%s err=%v", r.Host, err)
		http.Error(w, fmt.Sprintf("connect target failed: %v", err), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		log.Printf("hijack failed client=%s target=%s err=%v", r.RemoteAddr, r.Host, err)
		http.Error(w, fmt.Sprintf("hijack failed: %v", err), http.StatusInternalServerError)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		targetConn.Close()
		return
	}

	go transfer(targetConn, rw)
	go transfer(clientConn, targetConn)
}

func (p *ProxyServer) handleSOCKS5(conn net.Conn) {
	startedAt := time.Now()
	clientAddr := conn.RemoteAddr().String()
	target := ""
	status := "ok"

	defer func() {
		log.Printf(
			"client=%s proto=socks5 target=%s status=%s duration=%s",
			clientAddr,
			target,
			status,
			time.Since(startedAt).Round(time.Millisecond),
		)
	}()

	if err := p.negotiateSOCKS5Auth(conn); err != nil {
		status = err.Error()
		conn.Close()
		return
	}

	request, err := readSOCKS5Request(conn)
	if err != nil {
		status = err.Error()
		conn.Close()
		return
	}
	target = request.target

	if request.command != socksCommandConnect {
		status = "unsupported_command"
		_ = writeSOCKS5Reply(conn, socksReplyCommandUnsupported, nil)
		conn.Close()
		return
	}

	targetConn, err := net.DialTimeout("tcp", request.target, 10*time.Second)
	if err != nil {
		status = "connect_failed"
		log.Printf("socks5 connect target failed target=%s err=%v", request.target, err)
		_ = writeSOCKS5Reply(conn, mapSOCKS5DialError(err), nil)
		conn.Close()
		return
	}

	if err := writeSOCKS5Reply(conn, socksReplySucceeded, targetConn.LocalAddr()); err != nil {
		status = "reply_failed"
		targetConn.Close()
		conn.Close()
		return
	}

	go transfer(targetConn, conn)
	go transfer(conn, targetConn)
}

func transfer(dst net.Conn, src io.Reader) {
	defer dst.Close()
	if closer, ok := src.(io.Closer); ok {
		defer closer.Close()
	}
	if _, err := io.Copy(dst, src); err != nil && !isClosedNetworkError(err) {
		log.Printf("tunnel copy failed: %v", err)
	}
}

func (p *ProxyServer) authorized(r *http.Request) bool {
	if !p.authEnabled() {
		return true
	}

	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		log.Printf("proxy auth missing client=%s method=%s target=%s", r.RemoteAddr, r.Method, requestTarget(r))
		return false
	}

	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		log.Printf("proxy auth invalid scheme client=%s method=%s target=%s", r.RemoteAddr, r.Method, requestTarget(r))
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("proxy auth decode failed client=%s method=%s target=%s err=%v", r.RemoteAddr, r.Method, requestTarget(r), err)
		return false
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		log.Printf("proxy auth malformed client=%s method=%s target=%s", r.RemoteAddr, r.Method, requestTarget(r))
		return false
	}

	if username != p.auth.Username || password != p.auth.Password {
		log.Printf("proxy auth rejected client=%s method=%s target=%s username=%s", r.RemoteAddr, r.Method, requestTarget(r), username)
		return false
	}

	return true
}

func (p *ProxyServer) authEnabled() bool {
	return p.auth != nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isClosedNetworkError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func requestTarget(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return r.Host
	}

	if r.URL == nil {
		return ""
	}

	sanitized := *r.URL
	sanitized.User = nil
	return sanitized.String()
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) peekByte() (byte, error) {
	peeked, err := c.reader.Peek(1)
	if err != nil {
		return 0, err
	}
	return peeked[0], nil
}

type connListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{
		addr:  addr,
		conns: make(chan net.Conn, 128),
		done:  make(chan struct{}),
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() {
		close(l.done)
	})
	return nil
}

func (l *connListener) Addr() net.Addr {
	return l.addr
}

func (l *connListener) Deliver(conn net.Conn) error {
	select {
	case <-l.done:
		return net.ErrClosed
	case l.conns <- conn:
		return nil
	}
}

type socks5Request struct {
	command byte
	target  string
}

func (p *ProxyServer) negotiateSOCKS5Auth(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("method_read_failed")
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("invalid_version")
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("method_read_failed")
	}

	selectedMethod := byte(socksAuthNoAcceptableMethod)
	if p.authEnabled() {
		if containsByte(methods, socksAuthUsernamePassword) {
			selectedMethod = socksAuthUsernamePassword
		}
	} else if containsByte(methods, socksAuthNone) {
		selectedMethod = socksAuthNone
	}

	if _, err := conn.Write([]byte{socksVersion5, selectedMethod}); err != nil {
		return fmt.Errorf("method_write_failed")
	}
	if selectedMethod == socksAuthNoAcceptableMethod {
		return fmt.Errorf("no_acceptable_auth")
	}
	if selectedMethod != socksAuthUsernamePassword {
		return nil
	}

	username, password, err := readSOCKS5Credentials(conn)
	if err != nil {
		_ = writeSOCKS5AuthReply(conn, 0x01)
		return err
	}
	if username != p.auth.Username || password != p.auth.Password {
		_ = writeSOCKS5AuthReply(conn, 0x01)
		log.Printf("socks5 auth rejected client=%s username=%s", conn.RemoteAddr(), username)
		return fmt.Errorf("auth_failed")
	}

	if err := writeSOCKS5AuthReply(conn, 0x00); err != nil {
		return fmt.Errorf("auth_write_failed")
	}
	return nil
}

func readSOCKS5Credentials(conn net.Conn) (string, string, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", "", fmt.Errorf("auth_read_failed")
	}
	if header[0] != socksAuthVersion {
		return "", "", fmt.Errorf("invalid_auth_version")
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", "", fmt.Errorf("auth_read_failed")
	}

	var passwordLen [1]byte
	if _, err := io.ReadFull(conn, passwordLen[:]); err != nil {
		return "", "", fmt.Errorf("auth_read_failed")
	}

	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", "", fmt.Errorf("auth_read_failed")
	}

	return string(username), string(password), nil
}

func readSOCKS5Request(conn net.Conn) (*socks5Request, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, fmt.Errorf("request_read_failed")
	}
	if header[0] != socksVersion5 {
		return nil, fmt.Errorf("invalid_request_version")
	}

	host, err := readSOCKS5Address(conn, header[3])
	if err != nil {
		if errors.Is(err, errSOCKS5AddressUnsupported) {
			_ = writeSOCKS5Reply(conn, socksReplyAddressUnsupported, nil)
		}
		return nil, err
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return nil, fmt.Errorf("request_read_failed")
	}

	return &socks5Request{
		command: header[1],
		target:  net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(portBytes[:]))),
	}, nil
}

var errSOCKS5AddressUnsupported = errors.New("address_unsupported")

func readSOCKS5Address(conn net.Conn, addressType byte) (string, error) {
	switch addressType {
	case socksAddressTypeIPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("request_read_failed")
		}
		return net.IP(addr).String(), nil
	case socksAddressTypeIPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("request_read_failed")
		}
		return net.IP(addr).String(), nil
	case socksAddressTypeDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", fmt.Errorf("request_read_failed")
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, host); err != nil {
			return "", fmt.Errorf("request_read_failed")
		}
		return string(host), nil
	default:
		return "", errSOCKS5AddressUnsupported
	}
}

func writeSOCKS5AuthReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{socksAuthVersion, status})
	return err
}

func writeSOCKS5Reply(conn net.Conn, reply byte, addr net.Addr) error {
	addressType := byte(socksAddressTypeIPv4)
	address := []byte{0, 0, 0, 0}
	port := uint16(0)

	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		port = uint16(tcpAddr.Port)
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			addressType = socksAddressTypeIPv4
			address = ip4
		} else if ip16 := tcpAddr.IP.To16(); ip16 != nil {
			addressType = socksAddressTypeIPv6
			address = ip16
		}
	}

	response := make([]byte, 0, 6+len(address))
	response = append(response, socksVersion5, reply, 0x00, addressType)
	response = append(response, address...)
	response = binary.BigEndian.AppendUint16(response, port)
	_, err := conn.Write(response)
	return err
}

func mapSOCKS5DialError(err error) byte {
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return socksReplyConnectionRefused
	}
	return socksReplyGeneralFailure
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	return hijacker.Hijack()
}
