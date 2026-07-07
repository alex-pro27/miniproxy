package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
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

	log.Printf("proxy listening on %s auth=%t", config.Listen, proxy.authEnabled())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	if !p.authorized(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	p.handleHTTP(w, r)
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
		return false
	}

	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}

	return username == p.auth.Username && password == p.auth.Password
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
