// MIT License
//
// Copyright (c) 2024 quantix
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/bind/types.go
package bind

import (
	"github.com/ramseyauron/quantix/src/consensus"
	"github.com/ramseyauron/quantix/src/core"
	security "github.com/ramseyauron/quantix/src/handshake"
	"github.com/ramseyauron/quantix/src/http"
	"github.com/ramseyauron/quantix/src/network"
	"github.com/ramseyauron/quantix/src/p2p"
	"github.com/ramseyauron/quantix/src/rpc"
	"github.com/ramseyauron/quantix/src/transport"
)

// NodeConfig defines the configuration for a node’s TCP server.
// NodeConfig defines the configuration for a TCP server.
type NodeConfig struct {
	Address   string
	Name      string
	MessageCh chan *security.Message
	RPCServer *rpc.Server
	ReadyCh   chan struct{}
}

// NodeSetupConfig defines the configuration for setting up a node’s servers.
type NodeSetupConfig struct {
	Address   string
	Name      string
	Role      network.NodeRole
	HTTPPort  string
	WSPort    string
	UDPPort   string
	SeedNodes []string
}

// NodeResources holds the initialized resources for a node.
type NodeResources struct {
	Blockchain           *core.Blockchain
	NodeManager          *network.NodeManager
	ConsensusNodeManager consensus.NodeManager // Add this if needed
	MessageCh            chan *security.Message
	RPCServer            *rpc.Server
	P2PServer            *p2p.Server
	PublicKey            string
	TCPServer            *transport.TCPServer
	WebSocketServer      *transport.WebSocketServer
	HTTPServer           *http.Server
}
