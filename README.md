# DriveStreamer

A secure web-based disk backup and restore utility with streaming capabilities. No data is stored on the server - everything is streamed directly to/from the client.

## Features

- **Complete Disk Backup**: Create full disk images with streaming download
- **Image Restoration**: Restore disk images via web interface
- **Compression**: Support for XZ (better ratio) and ZSTD (faster) compression
- **Security**: Optional authentication and HTTPS support
- **Integrity**: SHA256 checksums for all dumps
- **Internationalization**: English and French interfaces with automatic language detection
- **Zero Storage**: All operations stream directly - no server storage required

## Requirements

### Required Tools
- `dd` - Disk reading/writing
- `lsblk` - Device listing
- `sha256sum` - Checksum calculation

### Optional Tools
- `xz` - XZ compression support
- `zstd` - ZSTD compression support
- `openssl` - For password hash verification

## Installation

### Quick Start

```bash
# Build the tool
./build.sh build

# Run without authentication
sudo ./drivestreamer

# Run with password authentication
sudo ./drivestreamer -password mySecurePassword

# Run with HTTPS
sudo ./drivestreamer -https -cert cert.pem -key key.pem
```

### Build Options

```bash
# Full release build
./build.sh release

# Build for current platform only
./build.sh build

# Build static binary
./build.sh build --static

# Cross-compile for all platforms
./build.sh cross

# Build Docker image
./build.sh docker
```

## Usage

### Command Line Options

```bash
drivestreamer [options]

Options:
  -port string
        Server listening port (default "8080")
  -password string
        Plain text password for authentication
  -password-hash string
        Password hash (bcrypt or crypt)
  -https
        Enable HTTPS
  -cert string
        TLS certificate file (default "cert.pem")
  -key string
        TLS private key file (default "key.pem")
  -help
        Show help
  -version
        Show version information
```

### Examples

#### Basic Usage (No Authentication)
```bash
sudo ./drivestreamer
```
Access at http://localhost:8080

#### With Password Protection
```bash
sudo ./drivestreamer -password "MySecurePassword123"
```

#### With HTTPS
First, generate a self-signed certificate:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Then run with HTTPS:
```bash
sudo ./drivestreamer -https -cert cert.pem -key key.pem
```
Access at https://localhost:8080

#### With Bcrypt Password Hash
```bash
# Generate hash
htpasswd -bnBC 10 "" "mypassword" | tr -d ':\n' | sed 's/$2y/$2b/'

# Use the hash
sudo ./drivestreamer -password-hash '$2b$10$...'
```

## Security Considerations

1. **Always use HTTPS in production** to encrypt data in transit
2. **Use strong passwords** and consider using bcrypt hashes
3. **Run on trusted networks only** - this tool has direct disk access
4. **Verify checksums** after downloading dumps
5. **Root access required** - handle with care

## Disk Dump Process

1. Select source disk from dropdown
2. Choose compression type (XZ for size, ZSTD for speed)
3. Click "Start Dump"
4. Image streams directly to your browser as download
5. SHA256 checksum is calculated during transfer
6. View all checksums at `/checksums` page

## Disk Restore Process

1. Select image file to restore
2. Choose destination disk (⚠️ will be completely erased!)
3. Confirm by typing "CONFIRM"
4. Upload streams directly to disk

## Language Support

The interface automatically detects your browser language and supports:
- English (en)
- Français (fr)

You can manually change the language using the dropdown in the header.

## Building from Source

### Prerequisites
- Go 1.21 or higher
- Git

### Build Steps
```bash
# Clone repository
git clone <repository-url>
cd drivestreamer

# Download dependencies
go mod download

# Build
go build -o drivestreamer

# Or use the build script
./build.sh build
```

## Docker Support

### Build Docker Image
```bash
./build.sh docker
```

### Run with Docker
```bash
docker run -it --rm --privileged \
  -p 8080:8080 \
  drivestreamer:latest \
  -password mypassword
```

Note: `--privileged` is required for block device access.

## Troubleshooting

### Missing Dependencies
The tool will check for required commands on startup. Install missing tools:
```bash
# Debian/Ubuntu
sudo apt-get install coreutils util-linux xz-utils zstd

# RHEL/CentOS
sudo yum install coreutils util-linux xz zstd
```

### Permission Denied
This tool requires root access to read/write block devices:
```bash
sudo ./drivestreamer
```

### HTTPS Certificate Issues
For self-signed certificates, browsers will show a security warning. This is normal - proceed to the site.

## License

GNU GPLv3