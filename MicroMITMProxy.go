package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/gorilla/websocket"
)

const (
	// Optionally you can embed the Cert and Key directly here so that no 'ca.crt' and 'ca.key' files are needed
	// PEM-encoded CA Certificate and Private Key
	caCertificatePEM = `-----BEGIN CERTIFICATE-----
...
...INSERT YOUR CERTIFICATE HERE...
...
-----END CERTIFICATE-----`

	caPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
...
...INSERT YOUR PRIVATE KEY HERE...
...
-----END PRIVATE KEY-----`

	// Character set for generating correlation IDs
	correlationIDCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Length of the correlation ID
	correlationIDLength = 6

	// Default ports for HTTP and HTTPS
	defaultHTTPSPort = "443"
	defaultHTTPPort  = "80"

	// Supported URL schemes
	schemeHTTPS = "https"
	schemeHTTP  = "http"
	schemeWS    = "ws"
	schemeWSS   = "wss"

	// Direction indicators for logging
	directionRequest  = "request"
	directionResponse = "response"

	// Log types
	logTypeHTTPRequest  = "http_request"
	logTypeHTTPResponse = "http_response"
	logTypeWebSocketMsg = "websocket_message"
	logTypeError        = "error"
	logTypeInfo         = "info"
	logTypeStatusUp     = "up"

	// Port range for selecting random ports
	minPortNumber  = 49152
	maxPortNumber  = 65535
	maxPortRetries = 10000
)

var (
	version    string // Set via build flags: go build -ldflags="-X main.version=<your_version>"
	seededRand *mathrand.Rand
)

// ProxyServer represents the proxy with CA details and certificate cache
type ProxyServer struct {
	caCertificate *x509.Certificate
	caPrivateKey  *rsa.PrivateKey
	certCache     map[string]*tls.Certificate
	cacheMutex    sync.RWMutex
}

// HTTPRequestLogEntry logs details of an HTTP request
type HTTPRequestLogEntry struct {
	Type          string      `json:"type"`
	CorrelationID string      `json:"corrID"`
	Direction     string      `json:"direction"`
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	Header        http.Header `json:"header"`
	ClientAddr    string      `json:"clientAddr"`
	ServerAddr    string      `json:"serverAddr,omitempty"`
	Body          string      `json:"body"`
}

// HTTPResponseLogEntry logs details of an HTTP response
type HTTPResponseLogEntry struct {
	Type          string      `json:"type"`
	CorrelationID string      `json:"corrID"`
	Direction     string      `json:"direction"`
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	Status        string      `json:"status"`
	StatusCode    int         `json:"statusCode"`
	Header        http.Header `json:"header"`
	ClientAddr    string      `json:"clientAddr"`
	ServerAddr    string      `json:"serverAddr,omitempty"`
	Body          string      `json:"body"`
}

// WebSocketMessageLogEntry logs details of a WebSocket message
type WebSocketMessageLogEntry struct {
	Type          string `json:"type"`
	CorrelationID string `json:"corrID"`
	Direction     string `json:"direction"`
	MessageType   string `json:"messageType"`
	URL           string `json:"url"`
	ClientAddr    string `json:"clientAddr"`
	ServerAddr    string `json:"serverAddr"`
	Body          string `json:"body"`
}

// LogMessage represents a generic log message
type LogMessage struct {
	Type          string `json:"type"`
	CorrelationID string `json:"corrID"`
	Body          string `json:"body"`
}

// loadCertificateAuthority parses and loads the CA certificate and private key
func (proxy *ProxyServer) loadCertificateAuthority() error {
	var certPEMBytes, keyPEMBytes []byte
	var err error

	// Attempt to read CA certificate and key from files
	certPath := "ca.crt"
	keyPath := "ca.key"

	certExists, keyExists := fileExists(certPath), fileExists(keyPath)
	if certExists && keyExists {
		certPEMBytes, err = os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("unable to read CA certificate from %s: %v", certPath, err)
		}

		keyPEMBytes, err = os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("unable to read CA private key from %s: %v", keyPath, err)
		}
	} else {
		// Fallback to embedded PEM data
		certPEMBytes = []byte(caCertificatePEM)
		keyPEMBytes = []byte(caPrivateKeyPEM)
	}

	// Decode and parse the CA certificate
	certBlock, _ := pem.Decode(certPEMBytes)
	if certBlock == nil {
		return fmt.Errorf("unable to decode CA certificate PEM")
	}
	proxy.caCertificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("invalid CA certificate: %v", err)
	}

	// Decode and parse the CA private key
	keyBlock, _ := pem.Decode(keyPEMBytes)
	if keyBlock == nil {
		return fmt.Errorf("unable to decode CA private key PEM")
	}

	parsedKey, parseErr := parsePrivateKey(keyBlock)
	if parseErr != nil {
		return fmt.Errorf("invalid CA private key: %v", parseErr)
	}

	var ok bool
	proxy.caPrivateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA private key is not an RSA key")
	}

	return nil
}

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// parsePrivateKey determines the type of private key and parses it accordingly
func parsePrivateKey(keyBlock *pem.Block) (interface{}, error) {
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyBlock.Type)
	}
}

// generateCertificate creates or retrieves a TLS certificate for the specified hostname
func (proxy *ProxyServer) generateCertificate(host string) (*tls.Certificate, error) {
	proxy.cacheMutex.RLock()
	if cert, exists := proxy.certCache[host]; exists {
		proxy.cacheMutex.RUnlock()
		return cert, nil
	}
	proxy.cacheMutex.RUnlock()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate serial number: %v", err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      proxy.caCertificate.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1-year validity
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, proxy.caCertificate, &privateKey.PublicKey, proxy.caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("certificate creation failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS key pair: %v", err)
	}

	proxy.cacheMutex.Lock()
	proxy.certCache[host] = &tlsCert
	proxy.cacheMutex.Unlock()

	return &tlsCert, nil
}

// logAsJSON marshals the log data to JSON and prints it
func logAsJSON(data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		errorLog := LogMessage{
			Type:          logTypeError,
			CorrelationID: "-error-",
			Body:          fmt.Sprintf("JSON marshaling failed: %v", err),
		}
		fallbackData, _ := json.Marshal(errorLog)
		fmt.Println(string(fallbackData))
		return
	}
	fmt.Println(string(jsonData))
}

// generateCorrelationID creates a random alphanumeric string of predefined length
func generateCorrelationID() string {
	result := make([]byte, correlationIDLength)
	charsetLength := big.NewInt(int64(len(correlationIDCharset)))
	for i := 0; i < correlationIDLength; i++ {
		num, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "-err!-"
		}
		result[i] = correlationIDCharset[num.Int64()]
	}
	return string(result)
}

// handleTLSConnection manages HTTPS connections by performing a MITM
func (proxy *ProxyServer) handleTLSConnection(w http.ResponseWriter, r *http.Request) {
	correlationID := generateCorrelationID()

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host // Default to host if port is not specified
		port = defaultHTTPSPort
	}

	// Upgrade the connection to a raw TCP connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Connection hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Inform the client that the connection has been established
	fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Generate or retrieve the certificate for the target host
	cert, err := proxy.generateCertificate(host)
	if err != nil {
		logError(fmt.Sprintf("Certificate generation failed: %v", err), correlationID)
		clientConn.Close()
		return
	}

	// Initiate TLS handshake with the client using the generated certificate
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true, // Bypass client-side verification
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	err = tlsClientConn.Handshake()
	if err != nil {
		logError(fmt.Sprintf("TLS handshake with client failed: %v", err), correlationID)
		tlsClientConn.Close()
		return
	}

	// Establish a TLS connection to the target server
	serverAddress := net.JoinHostPort(host, port)
	tlsServerConn, err := tls.Dial("tcp", serverAddress, &tls.Config{
		InsecureSkipVerify: true, // Bypass server-side verification
	})
	if err != nil {
		logError(fmt.Sprintf("Connection to target server failed: %v", err), correlationID)
		tlsClientConn.Close()
		return
	}

	// Relay HTTPS traffic between client and server
	go func(clientConn, serverConn net.Conn, corrID string) {
		defer clientConn.Close()
		defer serverConn.Close()
		if err := proxy.relayHTTPSConnections(clientConn, serverConn); err != nil {
			logError(fmt.Sprintf("HTTPS relay error: %v", err), corrID)
		}
	}(tlsClientConn, tlsServerConn, correlationID)
}

// relayHTTPSConnections forwards data between client and server, handling HTTP and WebSocket communications
func (proxy *ProxyServer) relayHTTPSConnections(clientConn, serverConn net.Conn) error {
	clientReader := bufio.NewReader(clientConn)
	serverReader := bufio.NewReader(serverConn)

	for {
		// Assign a new correlation ID for each request-response cycle
		corrID := generateCorrelationID()

		// Parse the incoming HTTP request from the client
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				logError(fmt.Sprintf("Failed to read client request: %v", err), corrID)
			}
			return err
		}

		// Process and forward the HTTP request
		if err := proxy.processHTTPSRequest(req, clientConn, serverConn, serverReader, corrID); err != nil {
			return err
		}
	}
}

// processHTTPSRequest handles individual HTTPS requests and responses
func (proxy *ProxyServer) processHTTPSRequest(req *http.Request, clientConn, serverConn net.Conn, serverReader *bufio.Reader, correlationID string) error {
	// Read the complete request body
	var requestBody []byte
	if req.Body != nil {
		var err error
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			logError(fmt.Sprintf("Failed to read request body: %v", err), correlationID)
			return err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(requestBody))
	}

	targetURL := url.URL{
		Scheme:   schemeHTTPS,
		Host:     req.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}

	// Create and log the HTTP request entry
	requestLog := HTTPRequestLogEntry{
		Type:          logTypeHTTPRequest,
		CorrelationID: correlationID,
		Direction:     directionRequest,
		Method:        req.Method,
		URL:           targetURL.String(),
		Header:        req.Header,
		ClientAddr:    clientConn.RemoteAddr().String(),
		ServerAddr:    serverConn.RemoteAddr().String(),
		Body:          formatBody(requestBody),
	}
	logAsJSON(requestLog)

	// Remove RequestURI to prevent issues during forwarding
	req.RequestURI = ""

	// Forward the HTTP request to the target server
	if err := req.Write(serverConn); err != nil {
		logError(fmt.Sprintf("Failed to forward request to server: %v", err), correlationID)
		return err
	}

	// Read the HTTP response from the server
	resp, err := http.ReadResponse(serverReader, req)
	if err != nil {
		logError(fmt.Sprintf("Failed to read response from server: %v", err), correlationID)
		return err
	}
	defer resp.Body.Close()

	// Read the complete response body
	var responseBody []byte
	if resp.Body != nil {
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			logError(fmt.Sprintf("Failed to read response body: %v", err), correlationID)
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(responseBody))
	}

	// Create and log the HTTP response entry
	responseLog := HTTPResponseLogEntry{
		Type:          logTypeHTTPResponse,
		CorrelationID: correlationID,
		Method:        req.Method,
		URL:           targetURL.String(),
		Direction:     directionResponse,
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Header:        resp.Header,
		ClientAddr:    clientConn.RemoteAddr().String(),
		ServerAddr:    serverConn.RemoteAddr().String(),
		Body:          formatBody(responseBody),
	}
	logAsJSON(responseLog)

	// Forward the HTTP response back to the client
	if err := resp.Write(clientConn); err != nil {
		logError(fmt.Sprintf("Failed to send response to client: %v", err), correlationID)
		return err
	}

	// Detect if the connection has been upgraded to WebSocket
	if isWebSocketUpgrade(resp) {
		logInfo("WebSocket upgrade detected over HTTPS", correlationID)
		webSocketURL := url.URL{
			Scheme:   schemeWSS,
			Host:     req.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		proxy.handleWebSocketOverTLS(clientConn, serverConn, correlationID, webSocketURL.String())
		return nil
	}

	return nil
}

// isWebSocketUpgrade checks if the HTTP response signifies a WebSocket upgrade
func isWebSocketUpgrade(resp *http.Response) bool {
	connectionHeader := strings.ToLower(resp.Header.Get("Connection"))
	upgradeHeader := strings.ToLower(resp.Header.Get("Upgrade"))
	return strings.Contains(connectionHeader, "upgrade") && upgradeHeader == "websocket" && resp.StatusCode == http.StatusSwitchingProtocols
}

// formatBody ensures that the body is a valid UTF-8 string; otherwise, it returns a hexadecimal representation
func formatBody(body []byte) string {
	if utf8.Valid(body) {
		return string(body)
	}
	return fmt.Sprintf("%x", body)
}

// handleHTTPRequest manages standard HTTP requests
func (proxy *ProxyServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	correlationID := generateCorrelationID()

	// Read the complete request body
	var requestBody []byte
	if r.Body != nil {
		var err error
		requestBody, err = io.ReadAll(r.Body)
		if err != nil {
			logError(fmt.Sprintf("Failed to read request body: %v", err), correlationID)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(requestBody))
	}

	targetURL := url.URL{
		Scheme:   schemeHTTP,
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Create and log the HTTP request entry
	requestLog := HTTPRequestLogEntry{
		Type:          logTypeHTTPRequest,
		CorrelationID: correlationID,
		Direction:     directionRequest,
		Method:        r.Method,
		URL:           targetURL.String(),
		Header:        r.Header,
		ClientAddr:    r.RemoteAddr,
		Body:          formatBody(requestBody),
	}
	logAsJSON(requestLog)

	// Remove RequestURI to prevent issues during forwarding
	r.RequestURI = ""

	// Forward the HTTP request to the target server
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		logError(fmt.Sprintf("Failed to forward request: %v", err), correlationID)
		http.Error(w, "Error forwarding request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the complete response body
	var responseBody []byte
	if resp.Body != nil {
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			logError(fmt.Sprintf("Failed to read response body: %v", err), correlationID)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		resp.Body = io.NopCloser(bytes.NewReader(responseBody))
	}

	// Create and log the HTTP response entry
	responseLog := HTTPResponseLogEntry{
		Type:          logTypeHTTPResponse,
		CorrelationID: correlationID,
		Method:        r.Method,
		URL:           targetURL.String(),
		Direction:     directionResponse,
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Header:        resp.Header,
		ClientAddr:    r.RemoteAddr,
		Body:          formatBody(responseBody),
	}
	logAsJSON(responseLog)

	// Relay the HTTP response back to the client
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, bytes.NewReader(responseBody)); err != nil {
		logError(fmt.Sprintf("Failed to send response to client: %v", err), correlationID)
	}
}

// copyHeaders duplicates HTTP headers from source to destination
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// handleWebSocketUpgrade manages WebSocket connections initiated over HTTP
func (proxy *ProxyServer) handleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	correlationID := generateCorrelationID()

	// Upgrade the HTTP connection to a WebSocket connection
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logError(fmt.Sprintf("WebSocket upgrade failed: %v", err), correlationID)
		return
	}
	defer clientConn.Close()

	// Prepare headers for the target WebSocket server
	requestHeader := make(http.Header)
	copyHeaders(requestHeader, r.Header)

	// Establish connection to the target WebSocket server
	targetURL := url.URL{
		Scheme:   schemeWS,
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	targetConn, _, err := websocket.DefaultDialer.Dial(targetURL.String(), requestHeader)
	if err != nil {
		logError(fmt.Sprintf("Failed to connect to target WebSocket server: %v", err), correlationID)
		return
	}
	defer targetConn.Close()

	// Relay messages between client and server
	proxy.relayWebSocketMessages(clientConn, targetConn, correlationID, targetURL.String())
}

// relayWebSocketMessages facilitates bidirectional message forwarding between WebSocket client and server
func (proxy *ProxyServer) relayWebSocketMessages(clientConn, targetConn *websocket.Conn, correlationID, targetURL string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Forward messages from client to server
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err) {
					logError(fmt.Sprintf("Error reading from client WebSocket: %v", err), correlationID)
				}
				targetConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				break
			}

			// Log the client-to-server message
			wsLog := WebSocketMessageLogEntry{
				Type:          logTypeWebSocketMsg,
				CorrelationID: correlationID,
				URL:           targetURL,
				Direction:     directionRequest,
				MessageType:   websocketMessageTypeToString(messageType),
				ClientAddr:    clientConn.RemoteAddr().String(),
				ServerAddr:    targetConn.RemoteAddr().String(),
				Body:          formatBody(message),
			}
			logAsJSON(wsLog)

			// Forward the message to the target server
			if err := targetConn.WriteMessage(messageType, message); err != nil {
				logError(fmt.Sprintf("Failed to send message to server WebSocket: %v", err), correlationID)
				break
			}
		}
	}()

	// Forward messages from server to client
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := targetConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err) {
					logError(fmt.Sprintf("Error reading from server WebSocket: %v", err), correlationID)
				}
				clientConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				break
			}

			// Log the server-to-client message
			wsLog := WebSocketMessageLogEntry{
				Type:          logTypeWebSocketMsg,
				CorrelationID: correlationID,
				URL:           targetURL,
				Direction:     directionResponse,
				MessageType:   websocketMessageTypeToString(messageType),
				ClientAddr:    clientConn.RemoteAddr().String(),
				ServerAddr:    targetConn.RemoteAddr().String(),
				Body:          formatBody(message),
			}
			logAsJSON(wsLog)

			// Forward the message to the WebSocket client
			if err := clientConn.WriteMessage(messageType, message); err != nil {
				logError(fmt.Sprintf("Failed to send message to client WebSocket: %v", err), correlationID)
				break
			}
		}
	}()

	wg.Wait()
}

// handleWebSocketOverTLS manages WebSocket connections initiated over HTTPS
func (proxy *ProxyServer) handleWebSocketOverTLS(clientConn, serverConn net.Conn, correlationID, targetURL string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Relay messages from client to server
	go func() {
		defer wg.Done()
		clientReader := wsutil.NewReader(clientConn, ws.StateServerSide)
		for {
			header, err := clientReader.NextFrame()
			if err != nil {
				if err != io.EOF {
					logError(fmt.Sprintf("Error reading from client TLS WebSocket: %v", err), correlationID)
				}
				break
			}

			payload, err := io.ReadAll(clientReader)
			if err != nil {
				logError(fmt.Sprintf("Error reading payload from client TLS WebSocket: %v", err), correlationID)
				break
			}

			// Log the client-to-server TLS WebSocket message
			wsLog := WebSocketMessageLogEntry{
				Type:          logTypeWebSocketMsg,
				CorrelationID: correlationID,
				URL:           targetURL,
				Direction:     directionRequest,
				MessageType:   wsOpCodeToString(header.OpCode),
				ClientAddr:    clientConn.RemoteAddr().String(),
				ServerAddr:    serverConn.RemoteAddr().String(),
				Body:          formatBody(payload),
			}
			logAsJSON(wsLog)

			// Forward the message to the target server
			if err := wsutil.WriteClientMessage(serverConn, header.OpCode, payload); err != nil {
				logError(fmt.Sprintf("Failed to send message to server TLS WebSocket: %v", err), correlationID)
				break
			}
		}
	}()

	// Relay messages from server to client
	go func() {
		defer wg.Done()
		serverReader := wsutil.NewReader(serverConn, ws.StateClientSide)
		for {
			header, err := serverReader.NextFrame()
			if err != nil {
				if err != io.EOF {
					logError(fmt.Sprintf("Error reading from server TLS WebSocket: %v", err), correlationID)
				}
				break
			}

			payload, err := io.ReadAll(serverReader)
			if err != nil {
				logError(fmt.Sprintf("Error reading payload from server TLS WebSocket: %v", err), correlationID)
				break
			}

			// Log the server-to-client TLS WebSocket message
			wsLog := WebSocketMessageLogEntry{
				Type:          logTypeWebSocketMsg,
				CorrelationID: correlationID,
				URL:           targetURL,
				Direction:     directionResponse,
				MessageType:   wsOpCodeToString(header.OpCode),
				ClientAddr:    clientConn.RemoteAddr().String(),
				ServerAddr:    serverConn.RemoteAddr().String(),
				Body:          formatBody(payload),
			}
			logAsJSON(wsLog)

			// Forward the message to the WebSocket client
			if err := wsutil.WriteServerMessage(clientConn, header.OpCode, payload); err != nil {
				logError(fmt.Sprintf("Failed to send message to client TLS WebSocket: %v", err), correlationID)
				break
			}
		}
	}()

	wg.Wait()
}

// logError logs an error message with the specified correlation ID
func logError(message, correlationID string) {
	errorLog := LogMessage{
		Type:          logTypeError,
		CorrelationID: correlationID,
		Body:          message,
	}
	logAsJSON(errorLog)
}

// logInfo logs an informational message with the specified correlation ID
func logInfo(message, correlationID string) {
	infoLog := LogMessage{
		Type:          logTypeInfo,
		CorrelationID: correlationID,
		Body:          message,
	}
	logAsJSON(infoLog)
}

// logStatusUp logs a status update message with the specified correlation ID
func logStatusUp(message, correlationID string) {
	statusLog := LogMessage{
		Type:          logTypeStatusUp,
		CorrelationID: correlationID,
		Body:          message,
	}
	logAsJSON(statusLog)
}

// websocketMessageTypeToString converts WebSocket message types to string representations
func websocketMessageTypeToString(messageType int) string {
	switch messageType {
	case websocket.TextMessage:
		return "TextMessage"
	case websocket.BinaryMessage:
		return "BinaryMessage"
	case websocket.CloseMessage:
		return "CloseMessage"
	case websocket.PingMessage:
		return "PingMessage"
	case websocket.PongMessage:
		return "PongMessage"
	default:
		return fmt.Sprintf("UnknownMessageType(%d)", messageType)
	}
}

// wsOpCodeToString converts WebSocket opcodes to string representations
func wsOpCodeToString(opCode ws.OpCode) string {
	switch opCode {
	case ws.OpContinuation:
		return "Continuation"
	case ws.OpText:
		return "Text"
	case ws.OpBinary:
		return "Binary"
	case ws.OpClose:
		return "Close"
	case ws.OpPing:
		return "Ping"
	case ws.OpPong:
		return "Pong"
	default:
		return fmt.Sprintf("UnknownOpCode(%d)", opCode)
	}
}

// getRandomPort selects an available port within the specified range
func getRandomPort(min, max int) (int, error) {
	for i := 0; i < maxPortRetries; i++ {
		port := seededRand.Intn(max-min+1) + min
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue // Port is likely in use, try another
		}
		ln.Close() // Port is available
		return port, nil
	}
	return 0, errors.New("no available ports found within the specified range")
}

func main() {
	logInfo(fmt.Sprintf("Starting MicroMITMProxy version %v", version), "-main-")

	// Define command-line flags
	portFlag := flag.String("port", "", "Port for the server to listen on. If not specified, a random available port within the range will be used.")
	flag.Parse()

	var port int
	var err error

	// Initialize seeded random generator
	source := mathrand.NewSource(time.Now().UnixNano())
	seededRand = mathrand.New(source)

	if *portFlag != "" {
		// Validate user-specified port
		port, err = strconv.Atoi(*portFlag)
		if err != nil || port < 1 || port > maxPortNumber {
			logError(fmt.Sprintf("Invalid port number '%s': must be an integer between 1 and %d", *portFlag, maxPortNumber), "-main-")
			os.Exit(1)
		}
	} else {
		// Select a random available port within the range
		port, err = getRandomPort(minPortNumber, maxPortNumber)
		if err != nil {
			logError(fmt.Sprintf("Failed to select an open port: %v", err), "-main-")
			os.Exit(1)
		}
	}

	proxy := &ProxyServer{
		certCache: make(map[string]*tls.Certificate),
	}

	// Load the Certificate Authority (CA) details
	if err := proxy.loadCertificateAuthority(); err != nil {
		logError(fmt.Sprintf("Failed to load CA: %v", err), "-main-")
		os.Exit(1)
	}

	// Define the server address, binding exclusively to localhost
	serverAddress := fmt.Sprintf("127.0.0.1:%d", port)

	// Initialize the HTTP server with appropriate handlers
	server := &http.Server{
		Addr: serverAddress,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodConnect:
				// Handle HTTPS (TLS) connections
				proxy.handleTLSConnection(w, r)
			case websocket.IsWebSocketUpgrade(r):
				// Handle WebSocket connections over HTTP
				proxy.handleWebSocketUpgrade(w, r)
			default:
				// Handle standard HTTP requests
				proxy.handleHTTPRequest(w, r)
			}
		}),
	}

	// Log the selected port
	logStatusUp(strconv.Itoa(port), "-main-")

	// Start the server and listen for incoming connections
	if err := server.ListenAndServe(); err != nil {
		logError(fmt.Sprintf("Server encountered an error: %v", err), "-main-")
		os.Exit(1)
	}
}
