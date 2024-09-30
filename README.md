# MicroMITMProxy

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**MicroMITMProxy** is a lightweight, standalone Go-based TLS-capable MITM proxy designed for intercepting HTTP, HTTPS, WS, and WSS (WebSocket Secure) traffic. Operating seamlessly as a sidecar application or independently, it outputs all intercepted traffic—including HTTP requests, responses, and WebSocket messages—in JSON format to stdout for easy analysis. By performing man-in-the-middle (MITM) interception using a custom Certificate Authority (CA), MicroMITMProxy decrypts and logs secure traffic. Requiring only a single binary and the certificate files, it has no external dependencies.

## Features

- **HTTP and HTTPS Interception**: Capture and log all HTTP and HTTPS traffic transparently.
- **WebSocket Support**: Intercept and log WebSocket upgrade requests and subsequent message frames.
- **Man-in-the-Middle (MITM)**: Decrypt HTTPS traffic using a custom CA certificate.
- **JSON-formatted Logging**: Outputs all data to `stdout` in JSON format for easy parsing and analysis.
- **Correlation IDs**: Assigns unique correlation IDs to requests and responses for easy tracking.
- **Random or Custom Port Selection**: Choose a specific port or allow the proxy to select a random available port.
- **Easy Integration**: Designed to operate as a sidecar, making it ideal for integration into existing environments.

## Table of Contents

- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
- [Usage](#usage)
  - [Running the Proxy](#running-the-proxy)
  - [Command-line Options](#command-line-options)
- [Generating Certificates](#generating-certificates)
  - [Generating CA Certificate and Key](#generating-ca-certificate-and-key)
  - [Embedding Certificates](#embedding-certificates)
  - [Using External Certificates](#using-external-certificates)
- [Installing the CA Certificate](#installing-the-ca-certificate)
  - [Firefox](#firefox)
  - [Chromium-based Browsers](#chromium-based-browsers)
  - [Operating System](#operating-system)
- [Output Format](#output-format)
- [Examples](#examples)
- [Go OS Compatibility](#go-os-compatibility)
- [License](#license)

## Installation

### Prerequisites

- **Go 1.16+** installed on your system **for building**.

  > **Note**: Go is only required for building the binary. The compiled Go binary is statically linked and requires **no Go runtime environment** to run.
- **OpenSSL** (optional, for generating certificates).

### Building from Source

#### One-line Command to Get Dependencies

You can automatically fetch all the dependencies and build the project with a single command:

```bash
go build -ldflags="-X main.version=1.0.0" -o micromitmproxy MicroMITMProxy.go
```

This command will download all required modules and build the binary.

Alternatively, you can initialize Go modules and fetch dependencies explicitly:

```bash
# Navigate to the project directory
cd MicroMITMProxy

# Initialize a new Go module (if not already done)
go mod init github.com/webermania/MicroMITMProxy

# Fetch all dependencies
go mod tidy

# Build the binary
go build -ldflags="-X main.version=1.0.0" -o micromitmproxy MicroMITMProxy.go
```

> **Note**: The resulting binary is a standalone executable and can be run on any compatible system without needing a Go installation.

## Usage

### Running the Proxy

By default, MicroMITMProxy selects a random available port between `49152` and `65535`. You can run the proxy without any arguments:

```bash
./micromitmproxy
```

### Command-line Options

- `-port`: Specify a custom port for the proxy to listen on.

```bash
./micromitmproxy -port 8080
```

## Generating Certificates

MicroMITMProxy requires a CA certificate and private key to perform MITM on HTTPS traffic. You can either embed them directly into the code or provide external `ca.crt` and `ca.key` files.

### Generating CA Certificate and Key

You can generate your own CA certificate and private key using OpenSSL. Here are the commands:

```bash
# Generate a 2048-bit RSA private key
openssl genrsa -out ca.key 2048

# Generate a self-signed X.509 certificate valid for 1024 days
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt \
  -subj "/O=MicroMITMProxy/CN=MicroMITMProxy-CA"
```

**Explanation:**

- `openssl genrsa -out ca.key 2048` generates a 2048-bit RSA private key and saves it as `ca.key`.
- `openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt ...` generates a self-signed X.509 certificate (`ca.crt`) valid for 1024 days, using the private key `ca.key`. The `-subj` flag sets the subject fields of the certificate.

### Embedding Certificates

To embed certificates directly into the code:

1. Generate the CA certificate and key as shown above.
2. Open `MicroMITMProxy.go` and locate the constants `caCertificatePEM` and `caPrivateKeyPEM`.
3. Replace the placeholders with your certificate and key contents:

```go
const (
    caCertificatePEM = `-----BEGIN CERTIFICATE-----
...YOUR CERTIFICATE HERE...
-----END CERTIFICATE-----`

    caPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
...YOUR PRIVATE KEY HERE...
-----END PRIVATE KEY-----`
)
```

4. Rebuild the binary:

```bash
go build -ldflags="-X main.version=1.0.0" -o micromitmproxy MicroMITMProxy.go
```

### Using External Certificates

Alternatively, you can place your `ca.crt` and `ca.key` files in the same directory as the binary. The proxy will automatically detect and use them.

## Installing the CA Certificate

To allow your browser or system to trust the certificates generated by MicroMITMProxy, you need to install the `ca.crt` file as a trusted CA.

### Firefox

1. Open **Settings** > **Privacy & Security**.
2. Scroll down to the **Certificates** section and click on **View Certificates**.
3. Go to the **Authorities** tab and click **Import**.
4. Select the `ca.crt` file and import it.
5. When prompted, check the option to **Trust this CA to identify websites**.

### Chromium-based Browsers

Chromium browsers (like Chrome, Edge) use the operating system's certificate store. Follow the instructions for your operating system below.

### Operating System

#### Windows

1. Press `Win + R`, type `certmgr.msc`, and press `Enter` to open the Certificate Manager.
2. Navigate to **Trusted Root Certification Authorities** > **Certificates**.
3. Right-click on **Certificates**, select **All Tasks** > **Import**.
4. Follow the wizard to import the `ca.crt` file.

#### macOS

1. Open **Keychain Access** from `Applications` > `Utilities`.
2. Select the **System** keychain.
3. Go to **File** > **Import Items** and select the `ca.crt` file.
4. After importing, double-click the certificate in the list, expand **Trust**, and set **When using this certificate** to **Always Trust**.

#### Linux

Instructions may vary depending on the distribution and desktop environment.

- For Debian/Ubuntu:

  ```bash
  sudo cp ca.crt /usr/local/share/ca-certificates/
  sudo update-ca-certificates
  ```

- For RedHat/CentOS:

  ```bash
  sudo cp ca.crt /etc/pki/ca-trust/source/anchors/
  sudo update-ca-trust
  ```

## Output Format

MicroMITMProxy outputs all intercepted data in JSON format to `stdout`. Each log entry includes:

- **Type**: The type of message (`http_request`, `http_response`, `websocket_message`, `error`, `info`, `up`).
- **CorrelationID**: Unique ID to correlate requests and responses.
- **Direction**: `request` or `response`.
- **Method**: HTTP method used.
- **URL**: The full URL of the request.
- **Header**: HTTP headers.
- **Body**: The body of the request or response.

**Example log entry:**

```json
{
  "Type": "http_request",
  "CorrelationID": "abc123",
  "Direction": "request",
  "Method": "GET",
  "URL": "https://example.com/api",
  "Header": {
    "User-Agent": ["Mozilla/5.0"],
    "Accept": ["*/*"]
  },
  "ClientAddr": "127.0.0.1:12345",
  "Body": ""
}
```

## Examples

### Starting the Proxy on a Custom Port

```bash
./micromitmproxy -port 8080
```

### Running with Embedded Certificates

Embed your `ca.crt` and `ca.key` contents into `MicroMITMProxy.go` as shown in [Embedding Certificates](#embedding-certificates) and rebuild the binary.

### Redirecting Output to a File

```bash
./micromitmproxy > logs.json
```

### Parsing Logs with `jq`

```bash
./micromitmproxy | jq '.'
```

## Go OS Compatibility

MicroMITMProxy is written in Go, which is a cross-platform language supporting multiple operating systems and architectures. The Go compiler produces statically compiled binaries that require **no external dependencies or runtime environments**.

Supported operating systems include:

- **Windows**: 32-bit and 64-bit.
- **macOS**: Supports both Intel and Apple Silicon processors.
- **Linux**: Various distributions and architectures.
- **FreeBSD**, **NetBSD**, **OpenBSD**.
- **Solaris**.

This cross-platform compatibility allows you to deploy MicroMITMProxy in diverse environments without worrying about runtime dependencies.

> **Note**: After building the binary with Go, you can distribute and run it on any compatible system without needing to install Go or any additional runtime.
