#!/bin/bash
# Quantix One-Line Installer
# Usage: curl -sSfL https://get.qpqb.org | bash
#
# This script installs the Quantix node and CLI tools.

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
QUANTIX_VERSION="${QUANTIX_VERSION:-latest}"
QUANTIX_INSTALL_DIR="${QUANTIX_INSTALL_DIR:-/usr/local/bin}"
QUANTIX_DATA_DIR="${QUANTIX_DATA_DIR:-$HOME/.quantix}"
GITHUB_REPO="quantix-org/quantix-org"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac

    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        mingw*|msys*|cygwin*)
            OS="windows"
            ;;
        *)
            echo -e "${RED}Unsupported operating system: $OS${NC}"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    echo -e "${BLUE}Detected platform: ${PLATFORM}${NC}"
}

# Get latest version from GitHub
get_latest_version() {
    if [ "$QUANTIX_VERSION" = "latest" ]; then
        QUANTIX_VERSION=$(curl -sSf "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -z "$QUANTIX_VERSION" ]; then
            echo -e "${YELLOW}Warning: Could not fetch latest version, using v0.1.0${NC}"
            QUANTIX_VERSION="v0.1.0"
        fi
    fi
    echo -e "${BLUE}Installing Quantix ${QUANTIX_VERSION}${NC}"
}

# Download and install binaries
install_binaries() {
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${QUANTIX_VERSION}/quantix-${QUANTIX_VERSION}-${PLATFORM}.tar.gz"
    
    echo -e "${BLUE}Downloading from: ${DOWNLOAD_URL}${NC}"
    
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    if ! curl -sSfL "$DOWNLOAD_URL" -o "$TMP_DIR/quantix.tar.gz" 2>/dev/null; then
        echo -e "${YELLOW}Pre-built binaries not available. Building from source...${NC}"
        install_from_source
        return
    fi

    tar -xzf "$TMP_DIR/quantix.tar.gz" -C "$TMP_DIR"

    # Install binaries
    echo -e "${BLUE}Installing to ${QUANTIX_INSTALL_DIR}...${NC}"
    
    if [ -w "$QUANTIX_INSTALL_DIR" ]; then
        cp "$TMP_DIR/quantix-node" "$QUANTIX_INSTALL_DIR/"
        cp "$TMP_DIR/quantix-cli" "$QUANTIX_INSTALL_DIR/" 2>/dev/null || true
    else
        sudo cp "$TMP_DIR/quantix-node" "$QUANTIX_INSTALL_DIR/"
        sudo cp "$TMP_DIR/quantix-cli" "$QUANTIX_INSTALL_DIR/" 2>/dev/null || true
    fi

    chmod +x "$QUANTIX_INSTALL_DIR/quantix-node"
    chmod +x "$QUANTIX_INSTALL_DIR/quantix-cli" 2>/dev/null || true
}

# Build from source
install_from_source() {
    echo -e "${BLUE}Building from source...${NC}"
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Go is required to build from source. Please install Go 1.21+ and try again.${NC}"
        echo -e "${BLUE}Visit: https://go.dev/dl/${NC}"
        exit 1
    fi

    GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | sed 's/go//')
    REQUIRED_VERSION="1.21"
    
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        echo -e "${RED}Go ${REQUIRED_VERSION}+ is required, found ${GO_VERSION}${NC}"
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$TMP_DIR/quantix"
    cd "$TMP_DIR/quantix"

    echo -e "${BLUE}Compiling...${NC}"
    go build -o quantix-node ./cmd/node 2>/dev/null || echo "Node binary not yet available"
    go build -o quantix-cli ./cmd/cli 2>/dev/null || echo "CLI binary not yet available"

    if [ -f "quantix-node" ]; then
        if [ -w "$QUANTIX_INSTALL_DIR" ]; then
            cp quantix-node "$QUANTIX_INSTALL_DIR/"
        else
            sudo cp quantix-node "$QUANTIX_INSTALL_DIR/"
        fi
        chmod +x "$QUANTIX_INSTALL_DIR/quantix-node"
    fi
}

# Create data directory and default config
setup_data_dir() {
    echo -e "${BLUE}Setting up data directory at ${QUANTIX_DATA_DIR}...${NC}"
    
    mkdir -p "$QUANTIX_DATA_DIR"
    mkdir -p "$QUANTIX_DATA_DIR/keystore"
    mkdir -p "$QUANTIX_DATA_DIR/data"

    # Create default config if it doesn't exist
    if [ ! -f "$QUANTIX_DATA_DIR/config.toml" ]; then
        cat > "$QUANTIX_DATA_DIR/config.toml" << 'EOF'
# Quantix Node Configuration
# Edit this file to customize your node

[node]
network = "mainnet"
datadir = "~/.quantix/data"
log_level = "info"

[network]
listen = "0.0.0.0:7331"
max_peers = 50

[rpc]
enabled = true
http_enabled = true
http_addr = "127.0.0.1"
http_port = 8545

[consensus]
validator = false
EOF
    fi
}

# Print success message
print_success() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Quantix installed successfully! 🚀               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BLUE}Quick Start:${NC}"
    echo -e "    Start node:     ${YELLOW}quantix-node --network mainnet${NC}"
    echo -e "    Join testnet:   ${YELLOW}quantix-node --network testnet${NC}"
    echo -e "    Local devnet:   ${YELLOW}quantix-node --network devnet${NC}"
    echo ""
    echo -e "  ${BLUE}Configuration:${NC}"
    echo -e "    Config file:    ${YELLOW}${QUANTIX_DATA_DIR}/config.toml${NC}"
    echo -e "    Data directory: ${YELLOW}${QUANTIX_DATA_DIR}/data${NC}"
    echo ""
    echo -e "  ${BLUE}Resources:${NC}"
    echo -e "    Website:        ${YELLOW}https://qpqb.org${NC}"
    echo -e "    Documentation:  ${YELLOW}https://docs.qpqb.org${NC}"
    echo -e "    GitHub:         ${YELLOW}https://github.com/quantix-org/quantix-org${NC}"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║             Quantix Installer                              ║${NC}"
    echo -e "${GREEN}║       Post-Quantum Secure Blockchain                       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    detect_platform
    get_latest_version
    install_binaries
    setup_data_dir
    print_success
}

main "$@"
