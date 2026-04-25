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

// go/src/http/types.go
package http

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/quantix-org/quantix-org/src/core"
	sign "github.com/quantix-org/quantix-org/src/core/sphincs/sign/backend"
	types "github.com/quantix-org/quantix-org/src/core/transaction"
	security "github.com/quantix-org/quantix-org/src/handshake"
)

// Server represents an HTTP server.
// ValidatorRegistrar is the interface for consensus-layer validator registration (P2-6).
type ValidatorRegistrar interface {
	RegisterValidator(id, pubkey string, stake uint64, nodeAddr string) error
	UnregisterValidator(id string) error
}

type Server struct {
	address               string
	router                *gin.Engine
	messageCh             chan *security.Message
	blockchain            *core.Blockchain
	httpServer            *http.Server
	lastTxMutex           sync.RWMutex
	lastTransaction       *types.Transaction
	readyCh               chan struct{}
	consensusValidatorSet ValidatorRegistrar   // P2-6: optional consensus validator set
	faucetLimiter         sync.Map             // P2-FAUCET: map[address]time.Time last request
	sphincsMgr            *sign.SphincsManager // P3-5: optional SPHINCS+ manager for sig verification
}

// SetConsensusValidatorSet wires the consensus validator set to the HTTP server (P2-6).
func (s *Server) SetConsensusValidatorSet(vr ValidatorRegistrar) {
	s.consensusValidatorSet = vr
}

// SetSphincsMgr wires a SphincsManager into the HTTP server for P3-5 sig verification.
func (s *Server) SetSphincsMgr(mgr *sign.SphincsManager) {
	s.sphincsMgr = mgr
}
