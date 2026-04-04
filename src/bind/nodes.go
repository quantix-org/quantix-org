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

// go/src/bind/nodes.go
package bind

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	nethttp "net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"math/big"

	"github.com/ramseyauron/quantix/src/common"
	"github.com/ramseyauron/quantix/src/consensus"
	"github.com/ramseyauron/quantix/src/core"
	database "github.com/ramseyauron/quantix/src/core/state"
	config "github.com/ramseyauron/quantix/src/core/sphincs/config"
	key "github.com/ramseyauron/quantix/src/core/sphincs/key/backend"
	sign "github.com/ramseyauron/quantix/src/core/sphincs/sign/backend"
	security "github.com/ramseyauron/quantix/src/handshake"
	"github.com/ramseyauron/quantix/src/http"
	logger "github.com/ramseyauron/quantix/src/log"
	"github.com/ramseyauron/quantix/src/network"
	"github.com/ramseyauron/quantix/src/p2p"
	"github.com/ramseyauron/quantix/src/rpc"
	"github.com/ramseyauron/quantix/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
)

// StartValidatorNode was StartSingleNode.
// Used by Charlie (validator node).
func StartValidatorNode(nodeConfig network.NodePortConfig, dataDir string) error {
	return StartSingleNodeInternal(nodeConfig, dataDir)
}

// StartLocalCluster was RunTwoNodes.
// Used to start multiple local test nodes (Alice, Bob, Charlie, etc.).
func StartLocalCluster() error {
	return RunMultipleNodesInternal()
}

// LaunchNetwork dynamically picks which to start.
//
//	mode = "validator" → Charlie single-node
//	mode = "cluster"   → local 3-node testnet
func LaunchNetwork(mode string) error {
	switch mode {
	case "validator":
		node := network.NodePortConfig{
			Name:      "Validator-Charlie",
			TCPAddr:   "127.0.0.1:32307",
			UDPPort:   "32418",
			HTTPPort:  "127.0.0.1:8645",
			WSPort:    "127.0.0.1:8700",
			Role:      network.RoleValidator,
			SeedNodes: []string{},
		}
		dataDir := common.DataDir // CHANGED: Use common test data directory
		return StartValidatorNode(node, dataDir)
	case "cluster":
		return StartLocalCluster()
	default:
		log.Printf("Unknown mode: %s. Use 'validator' or 'cluster'.", mode)
		os.Exit(1)
	}
	return nil
}

// StartSingleNode starts a single node with the given configuration
func StartSingleNodeInternal(nodeConfig network.NodePortConfig, dataDir string) error {
	// Use the provided dataDir; fall back to common.DataDir if empty.
	if dataDir != "" {
		common.DataDir = dataDir
	}
	nodeDataDir := common.GetNodeDataDir(nodeConfig.Name)
	if err := os.MkdirAll(nodeDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %v", nodeDataDir, err)
	}

	// Open LevelDB once — shared with SphincsManager and SetupNodes
	db, err := leveldb.OpenFile(common.GetLevelDBPath(nodeConfig.Name), nil)
	if err != nil {
		return fmt.Errorf("failed to open LevelDB for %s: %v", nodeConfig.Name, err)
	}
	// db is closed in the shutdown handler below after node stops
	keyManager, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize KeyManager: %v", err)
	}

	sphincsParams, err := config.NewSPHINCSParameters()
	if err != nil {
		return fmt.Errorf("failed to initialize SPHINCSParameters: %v", err)
	}

	sphincsMgr := sign.NewSphincsManager(db, keyManager, sphincsParams)
	if sphincsMgr == nil {
		return fmt.Errorf("failed to initialize SphincsManager")
	}

	// FIX-P2P-GOSSIP2: use TCPAddr as node name to ensure uniqueness across processes.
	// Without this, every single-node process is named "Node-0" causing ID collisions.
	nodeName := nodeConfig.Name
	if nodeConfig.TCPAddr != "" {
		nodeName = "Node-" + nodeConfig.TCPAddr
	}

	setupConfig := NodeSetupConfig{
		Name:      nodeName,
		Address:   nodeConfig.TCPAddr,
		DB:        db,
		UDPPort:   nodeConfig.UDPPort,
		HTTPPort:  nodeConfig.HTTPPort,
		WSPort:    nodeConfig.WSPort,
		Role:      nodeConfig.Role,
		SeedNodes:    nodeConfig.SeedNodes,
		SeedHTTPPort: nodeConfig.SeedHTTPPort,
		DevMode:      nodeConfig.DevMode, // FIX-P2P-03
	}

	var wg sync.WaitGroup
	resources, err := SetupNodes([]NodeSetupConfig{setupConfig}, &wg)
	if err != nil {
		return fmt.Errorf("failed to set up node %s: %v", nodeConfig.Name, err)
	}
	if len(resources) != 1 {
		return fmt.Errorf("expected 1 node resource, got %d", len(resources))
	}

	resources[0].P2PServer.SetSphincsMgr(sphincsMgr)

	// Re-inject DB into the resources blockchain (same object, belt-and-suspenders)
	resources[0].Blockchain.SetStorageDB(database.WrapLevelDB(db))
	resources[0].Blockchain.SetStateDB(database.WrapLevelDB(db))

	// Fix 1: dev-mode balance skip
	if nodeConfig.DevMode {
		resources[0].Blockchain.SetDevMode(true)
		log.Printf("⚠️  Dev-mode enabled for %s: balance checks skipped", nodeConfig.Name)
	}

	// P2-PBFT: Initialize and wire consensus engine to P2P layer.
	var pbftConsensus *consensus.Consensus
	{
		bc := resources[0].Blockchain
		p2pSrv := resources[0].P2PServer

		// Register VDF genesis hash provider (safe to call multiple times — only first call wins).
		bcRef := bc
		consensus.InitVDFFromGenesis(func() (string, error) {
			latest := bcRef.GetLatestBlock()
			if latest == nil {
				return "", fmt.Errorf("no blocks in storage")
			}
			if latest.GetHeight() == 0 {
				return latest.GetHash(), nil
			}
			current := latest.GetHash()
			for {
				block := bcRef.GetBlockByHash(current)
				if block == nil {
					return "", fmt.Errorf("chain traversal broken at %s", current)
				}
				if block.GetHeight() == 0 {
					return block.GetHash(), nil
				}
				current = block.GetPrevHash()
			}
		})

		// Build SPHINCS+ signing service for this node.
		nodeID := p2pSrv.LocalNode().ID
		km, err := key.NewKeyManager()
		if err != nil {
			return fmt.Errorf("P2-PBFT: key manager: %v", err)
		}
		sp, err := config.NewSPHINCSParameters()
		if err != nil {
			return fmt.Errorf("P2-PBFT: sphincs params: %v", err)
		}
		sm := sign.NewSphincsManager(db, km, sp)
		sigSvc := consensus.NewSigningService(sm, km, nodeID)
		if pk := sigSvc.GetPublicKeyObject(); pk != nil {
			sigSvc.RegisterPublicKey(nodeID, pk)
		}

		// Build P2P-backed node manager so consensus messages go over TCP.
		p2pNM := p2p.NewP2PNodeManager(p2pSrv.NodeManager())

		// Minimum stake from chain parameters.
		coreParams := core.GetQuantixChainParams()
		minStake := coreParams.ConsensusConfig.MinStakeAmount
		if minStake == nil {
			minStake = new(big.Int).Mul(big.NewInt(32), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		}

		cons := consensus.NewConsensus(nodeID, p2pNM, bc, sigSvc, nil, minStake)
		if cons == nil {
			log.Printf("⚠️  P2-PBFT: NewConsensus returned nil — PBFT disabled for %s", nodeName)
		} else {
			// Dev-mode: skip SPHINCS+ sig verification on votes/proposals.
			if nodeConfig.DevMode {
				cons.SetDevMode(true)
			}

			// Add self as validator with minimum stake.
			if vs := cons.GetValidatorSet(); vs != nil {
				_ = vs.AddValidator(nodeID, vs.GetMinStakeSPX())
			}

			// Wire consensus engine to blockchain and P2P server.
			bc.SetConsensusEngine(cons)
			bc.SetConsensus(cons)
			p2pSrv.InitializeConsensus(cons)

			// Register with the in-memory registry so local delivery also works.
			network.RegisterConsensus(nodeID, cons)

			// Only start the consensus engine when PBFT quorum is reachable.
			// With < 4 validators, the devnet miner goroutine below handles block
			// production.  Starting the engine anyway causes an endless view-change
			// loop (view 1 → 2 → 3 …) that holds consensus locks and prevents the
			// devnet miner from committing blocks.
			initialValidatorCount := 1 // self is always counted
			if initialValidatorCount >= 4 {
				if err := cons.Start(); err != nil {
					log.Printf("⚠️  P2-PBFT: consensus.Start failed: %v", err)
				} else {
					pbftConsensus = cons
					log.Printf("✅ P2-PBFT: consensus engine started for %s (dev-mode=%v)", nodeID, nodeConfig.DevMode)
				}
			} else {
				pbftConsensus = cons // keep reference for later activation at 4+ validators
				log.Printf("⏸️  P2-PBFT: consensus engine created but NOT started for %s — only %d validator(s), need %d for PBFT quorum (devnet miner active)",
					nodeID, initialValidatorCount, 4)
			}
		}
	}

	// P2-SYNC: if seeds are provided, build HTTP base URLs and sync from peers before live operation.
	if len(nodeConfig.SeedNodes) > 0 {
		seedHTTPPort := nodeConfig.SeedHTTPPort
		if seedHTTPPort == "" {
			seedHTTPPort = "8590"
		}
		seedHTTPs := make([]string, 0, len(nodeConfig.SeedNodes))
		for _, seed := range nodeConfig.SeedNodes {
			host, _, err := net.SplitHostPort(seed)
			if err != nil {
				host = seed
			}
			seedHTTPs = append(seedHTTPs, fmt.Sprintf("http://%s:%s", host, seedHTTPPort))
		}
		resources[0].Blockchain.SetSeedPeers(seedHTTPs)
		log.Printf("🔄 P2-SYNC: syncing from seed peers %v", seedHTTPs)
		if err := resources[0].Blockchain.SyncFromSeeds(); err != nil {
			log.Printf("⚠️  P2-SYNC warning: %v", err)
		}
	}

	// Fix 2: dev-mode peer validator auto-registration.
	// If seeds are provided, register this node with each seed and poll until
	// 4 validators are present, then the consensus engine will switch to PBFT.
	if nodeConfig.DevMode && len(nodeConfig.SeedNodes) > 0 {
		localNode := resources[0].P2PServer.LocalNode()
		myPubKey := hex.EncodeToString(localNode.PublicKey)
		myAddr := nodeConfig.TCPAddr
		go func() {
			// Wait for HTTP server to be ready
			time.Sleep(5 * time.Second)
			// Determine seed HTTP endpoints
			seedHTTPs := make([]string, 0, len(nodeConfig.SeedNodes))
			seedHTTPPort := nodeConfig.SeedHTTPPort
			if seedHTTPPort == "" {
				seedHTTPPort = "8560"
			}
			for _, seed := range nodeConfig.SeedNodes {
				host, _, err := net.SplitHostPort(seed)
				if err != nil {
					host = seed
				}
				seedHTTPs = append(seedHTTPs, fmt.Sprintf("http://%s:%s", host, seedHTTPPort))
			}

			// Register with each seed
			reg := core.ValidatorRegistration{
				PublicKey:    myPubKey,
				StakeAmount:  "1000000",
				NodeAddress:  myAddr,
				Active:       true,
				RegisteredAt: time.Now(),
			}
			regData, _ := json.Marshal(reg)
			for _, seedURL := range seedHTTPs {
				url := seedURL + "/validator/register"
				resp, err := nethttp.Post(url, "application/json", bytes.NewReader(regData)) //nolint:noctx
				if err != nil {
					log.Printf("⚠️  validator register to %s failed: %v", url, err)
					continue
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
				log.Printf("✅ Registered validator with seed %s (status %d)", seedURL, resp.StatusCode)
			}

			// Also register self on local HTTP
			localHTTPPort := nodeConfig.HTTPPort
			selfURL := "http://" + localHTTPPort + "/validator/register"
			resp, err := nethttp.Post(selfURL, "application/json", bytes.NewReader(regData)) //nolint:noctx
			if err == nil {
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}

			// Poll validator count; when >= 4, sync to consensus validatorSet and signal PBFT ready.
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			pbftReady := false
			for range ticker.C {
				validators, err := resources[0].Blockchain.GetValidators()
				if err != nil {
					continue
				}
				n := len(validators)
				log.Printf("🔍 Validator count: %d / 4", n)
				if n >= 4 && !pbftReady {
					pbftReady = true
					log.Printf("🎉 %s: 4 validators registered — syncing to consensus validatorSet", nodeConfig.Name)
					// P2-PBFT: sync all registered validators into the consensus validatorSet.
					cons := pbftConsensus
					if cons != nil {
						vs := cons.GetValidatorSet()
						if vs != nil {
							for _, vr := range validators {
								nodeAddr := vr.NodeAddress
								// Use node address as validator ID (matches how nodes identify)
								stake, ok := new(big.Int).SetString(vr.StakeAmount, 10)
								if !ok || stake.Sign() <= 0 {
									stake = new(big.Int).SetInt64(1000000)
								}
								// Convert to QTX units for the validator set
								stakeQTX := new(big.Int).Div(stake, big.NewInt(1e9)) // rough conversion
								if stakeQTX.Sign() <= 0 {
									stakeQTX = big.NewInt(1000)
								}
								_ = vs.AddValidator(nodeAddr, stakeQTX.Uint64())
								log.Printf("🔐 P2-PBFT: registered validator %s with stake %s in consensus", nodeAddr, stake.String())
							}
							log.Printf("✅ P2-PBFT: consensus validatorSet now has %d validators — PBFT active!", n)
						}
					}
					// Start the consensus engine now that quorum is reachable.
					if err := cons.Start(); err != nil {
						log.Printf("⚠️  P2-PBFT: consensus.Start failed at quorum: %v", err)
					} else {
						log.Printf("🚀 P2-PBFT: consensus engine started — PBFT quorum reached (%d validators)", n)
					}
					return
				}
			}
		}()
	}

	// P2-PBFT: For seed node (no seeds provided) in dev-mode, also poll for 4 validators
	// and sync them to the consensus validatorSet when quorum is reached.
	if nodeConfig.DevMode && len(nodeConfig.SeedNodes) == 0 && pbftConsensus != nil {
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			pbftReady := false
			cons := pbftConsensus
			for range ticker.C {
				validators, err := resources[0].Blockchain.GetValidators()
				if err != nil || len(validators) < 4 || pbftReady {
					continue
				}
				pbftReady = true
				log.Printf("🎉 Seed node: 4 validators — syncing consensus validatorSet")
				if vs := cons.GetValidatorSet(); vs != nil {
					for _, vr := range validators {
						stake, ok := new(big.Int).SetString(vr.StakeAmount, 10)
						if !ok || stake.Sign() <= 0 {
							stake = new(big.Int).SetInt64(1000000)
						}
						stakeQTX := new(big.Int).Div(stake, big.NewInt(1e9))
						if stakeQTX.Sign() <= 0 {
							stakeQTX = big.NewInt(1000)
						}
						_ = vs.AddValidator(vr.NodeAddress, stakeQTX.Uint64())
					}
					log.Printf("✅ P2-PBFT: seed node consensus validatorSet synced with %d validators", len(validators))
				}
				// Start the consensus engine now that quorum is reachable.
				if err := cons.Start(); err != nil {
					log.Printf("⚠️  P2-PBFT: seed node consensus.Start failed at quorum: %v", err)
				} else {
					log.Printf("🚀 P2-PBFT: seed node consensus engine started — PBFT quorum reached")
				}
				return
			}
		}()
	}

	// Devnet solo block producer — mines a new block every 10s from mempool
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("⚠️  Devnet miner recovered from panic: %v — restarting", r)
				// Restart after panic
				go func() {
					time.Sleep(5 * time.Second)
					log.Printf("🔄 Devnet miner restarting after panic")
					ticker2 := time.NewTicker(10 * time.Second)
					defer ticker2.Stop()
					bc2 := resources[0].Blockchain
					for range ticker2.C {
						if height, err := bc2.DevnetMineBlock(nodeConfig.Name); err != nil {
							if !strings.Contains(err.Error(), "no pending transactions") {
								log.Printf("⚠️  Devnet miner: %v", err)
							}
						} else {
							log.Printf("⛏️  Devnet mined block #%d", height)
						}
					}
				}()
			}
		}()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		bc := resources[0].Blockchain
		log.Printf("🔨 Devnet miner started for %s — producing blocks every 10s", nodeConfig.Name)
		for {
			select {
			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("⚠️  Devnet miner tick panic: %v", r)
						}
					}()
					pendingCount := bc.GetPendingTransactionCount()
					log.Printf("DevnetMineBlock attempt: pending=%d", pendingCount)
					height, err := bc.DevnetMineBlock(nodeConfig.Name)
					if err != nil {
						if !strings.Contains(err.Error(), "no pending transactions") {
							log.Printf("⚠️  Devnet miner: %v", err)
						}
					} else {
						log.Printf("⛏️  Devnet mined block #%d", height)
					}
				}()
			}
		}
	}()

	// Start peer discovery after setup
	go func() {
		if err := resources[0].P2PServer.DiscoverPeers(); err != nil {
			log.Printf("DiscoverPeers failed for %s: %v", nodeConfig.Name, err)
		}
	}()

	log.Printf("Node %s started with role %s on TCP %s, UDP %s, HTTP %s, WebSocket %s",
		nodeConfig.Name, nodeConfig.Role, nodeConfig.TCPAddr, nodeConfig.UDPPort, nodeConfig.HTTPPort, nodeConfig.WSPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("Shutting down node %s...", nodeConfig.Name)
	if err := Shutdown([]NodeResources{resources[0]}); err != nil {
		log.Printf("Failed to shut down node %s: %v", nodeConfig.Name, err)
	}
	wg.Wait()
	db.Close() // safe to close now — all goroutines done
	return nil
}

// RunTwoNodes starts three nodes with default configurations using the bind package.
func RunMultipleNodesInternal() error {
	// Initialize wait group
	var wg sync.WaitGroup

	// Initialize used ports map to avoid conflicts
	usedPorts := make(map[int]bool)

	// Define base ports
	const baseTCPPort = 32307
	const baseUDPPort = 32418
	const baseHTTPPort = 8645
	const baseWSPort = 8700

	configs := make([]network.NodePortConfig, 3)
	dbs := make([]*leveldb.DB, 3)
	sphincsMgrs := make([]*sign.SphincsManager, 3)

	// Initialize LevelDB and SphincsManager for each node
	for i := 0; i < 3; i++ {
		nodeName := fmt.Sprintf("Node-%d", i)

		// CHANGED: Use common functions for standardized paths
		dataDir := common.GetNodeDataDir(nodeName)
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory %s: %v", dataDir, err)
		}

		// CHANGED: Use common.GetLevelDBPath
		db, err := leveldb.OpenFile(common.GetLevelDBPath(nodeName), nil)
		if err != nil {
			return fmt.Errorf("failed to open LevelDB at %s: %v", dataDir, err)
		}
		dbs[i] = db

		keyManager, err := key.NewKeyManager()
		if err != nil {
			return fmt.Errorf("failed to initialize KeyManager for Node-%d: %v", i, err)
		}

		sphincsParams, err := config.NewSPHINCSParameters()
		if err != nil {
			return fmt.Errorf("failed to initialize SPHINCSParameters for Node-%d: %v", i, err)
		}

		sphincsMgr := sign.NewSphincsManager(db, keyManager, sphincsParams)
		if sphincsMgr == nil {
			return fmt.Errorf("failed to initialize SphincsManager for Node-%d", i)
		}
		sphincsMgrs[i] = sphincsMgr

		// Find free TCP port
		tcpPort, err := network.FindFreePort(baseTCPPort+i*2, "tcp")
		if err != nil {
			return fmt.Errorf("failed to find free TCP port for Node-%d: %v", i, err)
		}
		usedPorts[tcpPort] = true
		tcpAddr := fmt.Sprintf("127.0.0.1:%d", tcpPort)

		// Find free UDP port
		udpPort, err := network.FindFreePort(baseUDPPort+i*2, "udp")
		if err != nil {
			return fmt.Errorf("failed to find free UDP port for Node-%d: %v", i, err)
		}
		usedPorts[udpPort] = true
		udpPortStr := fmt.Sprintf("%d", udpPort)

		// Find free HTTP port
		httpPort, err := network.FindFreePort(baseHTTPPort+i, "tcp")
		if err != nil {
			return fmt.Errorf("failed to find free HTTP port for Node-%d: %v", i, err)
		}
		usedPorts[httpPort] = true
		httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)

		// Find free WebSocket port
		wsPort, err := network.FindFreePort(baseWSPort+i, "tcp")
		if err != nil {
			return fmt.Errorf("failed to find free WebSocket port for Node-%d: %v", i, err)
		}
		usedPorts[wsPort] = true
		wsAddr := fmt.Sprintf("127.0.0.1:%d", wsPort)

		configs[i] = network.NodePortConfig{
			ID:        nodeName,
			Name:      nodeName,
			TCPAddr:   tcpAddr,
			UDPPort:   udpPortStr,
			HTTPPort:  httpAddr,
			WSPort:    wsAddr,
			Role:      network.RoleNone,
			SeedNodes: []string{}, // Initialize empty; seeds will be set later
		}
		// Store initial config
		network.UpdateNodeConfig(configs[i])
	}

	// Convert []network.NodePortConfig to []NodeSetupConfig
	setupConfigs := make([]NodeSetupConfig, len(configs))
	for i, config := range configs {
		setupConfigs[i] = NodeSetupConfig{
			Name:         config.Name,
			Address:      config.TCPAddr,
			UDPPort:      config.UDPPort,
			HTTPPort:     config.HTTPPort,
			WSPort:       config.WSPort,
			Role:         config.Role,
			SeedNodes:    config.SeedNodes,
			SeedHTTPPort: config.SeedHTTPPort,
			DevMode:      config.DevMode, // FIX-P2P-03
		}
	}

	resources, err := SetupNodes(setupConfigs, &wg)
	if err != nil {
		return fmt.Errorf("failed to set up nodes: %v", err)
	}

	// Wait briefly to ensure P2P servers are initialized
	time.Sleep(2 * time.Second)
	for i := 0; i < 3; i++ {
		log.Printf("Checking P2P server for Node-%d: TCP=%s, UDP=%s", i, resources[i].P2PServer.LocalNode().Address, resources[i].P2PServer.LocalNode().UDPPort)
	}

	// Set SphincsManager for each P2PServer
	for i := 0; i < 3; i++ {
		resources[i].P2PServer.SetSphincsMgr(sphincsMgrs[i])
	}

	// Update seed nodes with actual UDP ports BEFORE calling DiscoverPeers
	for i, config := range configs {
		actualUDPPort := resources[i].P2PServer.LocalNode().UDPPort
		config.UDPPort = actualUDPPort
		seedNodes := []string{}
		for j := 0; j < 3; j++ {
			if j != i {
				seedConfig, exists := network.GetNodeConfig(fmt.Sprintf("Node-%d", j))
				if exists && seedConfig.UDPPort != "" {
					seedAddr := fmt.Sprintf("127.0.0.1:%s", seedConfig.UDPPort)
					// Validate seed node address
					if _, err := net.ResolveUDPAddr("udp", seedAddr); err != nil {
						log.Printf("Invalid seed node address for Node-%d: %s, error: %v", j, seedAddr, err)
						continue
					}
					seedNodes = append(seedNodes, seedAddr)
				}
			}
		}
		if len(seedNodes) == 0 {
			log.Printf("Warning: No valid seed nodes for Node-%d", i)
		}
		config.SeedNodes = seedNodes
		network.UpdateNodeConfig(config)
		resources[i].P2PServer.UpdateSeedNodes(config.SeedNodes)
		log.Printf("Updated seed nodes for Node-%d: %v", i, seedNodes)
	}

	// NOW call DiscoverPeers for each node
	for i := 0; i < 3; i++ {
		go func(idx int) {
			log.Printf("Starting DiscoverPeers for Node-%d", idx)
			if err := resources[idx].P2PServer.DiscoverPeers(); err != nil {
				log.Printf("DiscoverPeers failed for Node-%d: %v", idx, err)
			} else {
				log.Printf("DiscoverPeers completed successfully for Node-%d", idx)
			}
		}(i)
	}

	// Clear global configs and close databases on shutdown
	defer func() {
		network.ClearNodeConfigs()
		for i, db := range dbs {
			if err := db.Close(); err != nil {
				log.Printf("Failed to close LevelDB for Node-%d: %v", i, err)
			}
		}
	}()

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down servers...")
	if err := Shutdown(resources); err != nil {
		log.Printf("Failed to shut down servers: %v", err)
	}
	wg.Wait()
	return nil
}

// ParseRoles converts a comma-separated roles string into a slice of NodeRole.
func ParseRoles(rolesStr string, numNodes int) []network.NodeRole {
	roles := strings.Split(rolesStr, ",")
	result := make([]network.NodeRole, numNodes)
	for i := 0; i < numNodes; i++ {
		if i < len(roles) {
			switch strings.TrimSpace(roles[i]) {
			case "sender":
				result[i] = network.RoleSender
			case "receiver":
				result[i] = network.RoleReceiver
			case "validator":
				result[i] = network.RoleValidator
			default:
				result[i] = network.RoleNone
			}
		} else {
			result[i] = network.RoleNone
		}
	}
	return result
}

// SetupNodes initializes and starts all servers for the given node configurations.
func SetupNodes(configs []NodeSetupConfig, wg *sync.WaitGroup) ([]NodeResources, error) {
	messageChans := make([]chan *security.Message, len(configs))
	blockchains := make([]*core.Blockchain, len(configs))
	rpcServers := make([]*rpc.Server, len(configs))
	p2pServers := make([]*p2p.Server, len(configs))
	tcpServers := make([]*transport.TCPServer, len(configs))
	wsServers := make([]*transport.WebSocketServer, len(configs))
	httpServers := make([]*http.Server, len(configs))
	publicKeys := make(map[string]string)
	readyCh := make(chan struct{}, len(configs)*3)
	tcpReadyCh := make(chan struct{}, len(configs))
	p2pErrorCh := make(chan error, len(configs))
	udpReadyCh := make(chan struct{}, len(configs))
	dbs := make([]*leveldb.DB, len(configs))
	closed := make([]bool, len(configs))

	// Extract all validator addresses for the state machine
	allValidators := make([]string, len(configs))
	for i, config := range configs {
		allValidators[i] = config.Name // Using node names as validator IDs
	}

	// Initialize resources and TCP server configs
	tcpConfigs := make([]NodeConfig, len(configs))
	for i, config := range configs {
		parts := strings.Split(config.Address, ":")
		if len(parts) != 2 {
			logger.Errorf("Invalid address format for %s: %s", config.Name, config.Address)
			return nil, fmt.Errorf("invalid address format for %s: %s", config.Name, config.Address)
		}
		ip, port := parts[0], parts[1]
		if err := transport.ValidateIP(ip, port); err != nil {
			logger.Errorf("Invalid IP or port for %s: %v", config.Name, err)
			return nil, fmt.Errorf("invalid IP or port for %s: %v", config.Name, err)
		}

		logger.Infof("Initializing blockchain for %s", config.Name)
		// CHANGED: Use common.GetBlockchainDataDir for standardized blockchain path
		// CHANGED: Use common.GetBlockchainDataDir for standardized blockchain path
		dataDir := common.GetBlockchainDataDir(config.Name)
		// ADD NETWORK TYPE PARAMETER - use "devnet" for testing or get from config
		// This one is actually correct order — dataDir, nodeID, validators, networkType
		// BUT the networkType variable needs to be "devnet" not just hardcoded
		// Verify networkType is set before this call
		networkType := "devnet" // ensure this is present
		blockchain, err := core.NewBlockchain(dataDir, config.Name, allValidators, networkType)
		if err != nil {
			logger.Errorf("Failed to initialize blockchain for %s: %v", config.Name, err)
			return nil, fmt.Errorf("failed to initialize blockchain for %s: %w", config.Name, err)
		}
		blockchains[i] = blockchain

		// Wrap the already-open dbs[i] to avoid LevelDB double-lock.
		// database.WrapLevelDB shares the handle without re-opening the file.
		blockchain.SetStorageDB(database.WrapLevelDB(dbs[i]))
		blockchain.SetStateDB(database.WrapLevelDB(dbs[i]))
		logger.Infof("✅ Storage DB injected for %s — devnet miner enabled", config.Name)

		logger.Infof("Genesis block created for %s, hash: %x", config.Name, blockchains[i].GetBestBlockHash())
		// FIX-P2P-GOSSIP2: use a fanout pattern so TCP writes once but both
		// RPC and P2P servers receive every message independently.
		sourceCh := make(chan *security.Message, 1000) // TCP server writes here
		rpcCh := make(chan *security.Message, 1000)    // RPC server reads here
		p2pCh := make(chan *security.Message, 1000)    // P2P server reads here
		go func(src <-chan *security.Message, rpcDst, p2pDst chan<- *security.Message) {
			for msg := range src {
				select {
				case rpcDst <- msg:
				default:
				}
				select {
				case p2pDst <- msg:
				default:
				}
			}
		}(sourceCh, rpcCh, p2pCh)
		messageChans[i] = sourceCh // TCP server uses sourceCh
		rpcServers[i] = rpc.NewServer(rpcCh, blockchains[i])

		tcpConfigs[i] = NodeConfig{
			Address:   config.Address,
			Name:      config.Name,
			MessageCh: messageChans[i],
			RPCServer: rpcServers[i],
			ReadyCh:   tcpReadyCh,
		}

		// Reuse pre-opened DB if provided (avoids double-lock), otherwise open fresh
		if config.DB != nil {
			dbs[i] = config.DB
		} else {
			openedDB, dbErr := leveldb.OpenFile(common.GetLevelDBPath(config.Name), nil)
			if dbErr != nil {
				logger.Errorf("Failed to open LevelDB for %s: %v", config.Name, dbErr)
				return nil, fmt.Errorf("failed to open LevelDB for %s: %w", config.Name, dbErr)
			}
			dbs[i] = openedDB
		}

		// Initialize p2p.Server with NodePortConfig, ensuring Node.ID is set
		nodeConfig := network.NodePortConfig{
			ID:        config.Name,
			Name:      config.Name,
			TCPAddr:   config.Address,
			UDPPort:   config.UDPPort,
			HTTPPort:  config.HTTPPort,
			WSPort:    config.WSPort,
			Role:      config.Role,
			SeedNodes: config.SeedNodes,
			DevMode:   config.DevMode, // FIX-P2P-03
		}
		p2pServers[i] = p2p.NewServer(nodeConfig, blockchains[i], dbs[i])
		// FIX-P2P-GOSSIP2: use the p2pCh from the fanout above so the P2P server
		// receives all messages independently from the RPC server.
		p2pServers[i].SetMessageCh(p2pCh)
		localNode := p2pServers[i].LocalNode()
		localNode.ID = config.Name
		localNode.UpdateRole(config.Role)
		logger.Infof("Node %s initialized with ID %s and role %s", config.Name, localNode.ID, config.Role)

		if len(localNode.PublicKey) == 0 || len(localNode.PrivateKey) == 0 {
			logger.Errorf("Key generation failed for %s", config.Name)
			return nil, fmt.Errorf("key generation failed for %s", config.Name)
		}

		pubHex := hex.EncodeToString(localNode.PublicKey)
		logger.Infof("Node %s public key: %s", config.Name, pubHex)
		if _, exists := publicKeys[pubHex]; exists {
			logger.Errorf("Duplicate public key detected for %s: %s", config.Name, pubHex)
			return nil, fmt.Errorf("duplicate public key detected for %s: %s", config.Name, pubHex)
		}
		publicKeys[pubHex] = config.Name

		tcpServers[i] = transport.NewTCPServer(config.Address, messageChans[i], rpcServers[i], tcpReadyCh)
		wsServers[i] = transport.NewWebSocketServer(config.WSPort, messageChans[i], rpcServers[i])
		httpServers[i] = http.NewServer(config.HTTPPort, messageChans[i], blockchains[i], readyCh)
	}

	// Bind TCP servers
	if err := BindTCPServers(tcpConfigs, wg); err != nil {
		logger.Errorf("Failed to bind TCP servers: %v", err)
		return nil, err
	}

	// Wait for TCP servers to be ready
	logger.Infof("Waiting for %d TCP servers to be ready", len(configs))
	for i := 0; i < len(configs); i++ {
		select {
		case <-tcpReadyCh:
			logger.Infof("TCP server %d of %d ready", i+1, len(configs))
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for TCP server %d to be ready after 10s", i+1)
			return nil, fmt.Errorf("timeout waiting for TCP server %d to be ready after 10s", i+1)
		}
	}
	close(tcpReadyCh)
	logger.Infof("All TCP servers are ready")

	// Start P2P servers and wait for UDP listeners to be ready
	p2pReadyCh := make(chan struct{}, len(configs))
	for i, config := range configs {
		startP2PServer(config.Name, p2pServers[i], p2pReadyCh, p2pErrorCh, udpReadyCh, wg)
	}

	// Wait for all P2P servers to be ready or fail
	logger.Infof("Waiting for %d P2P servers to be ready", len(configs))
	for i := 0; i < len(configs); i++ {
		select {
		case <-p2pReadyCh:
			logger.Infof("P2P server %d of %d ready", i+1, len(configs))
		case err := <-p2pErrorCh:
			logger.Errorf("P2P server %d failed: %v", i+1, err)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("P2P server %d failed: %v", i+1, err)
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for P2P server %d to be ready", i+1)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("timeout waiting for P2P server %d to be ready", i+1)
		}
	}
	close(p2pReadyCh)

	// Wait for UDP listeners to be ready
	logger.Infof("Waiting for %d UDP listeners to be ready", len(configs))
	for i := 0; i < len(configs); i++ {
		select {
		case <-udpReadyCh:
			logger.Infof("UDP listener %d of %d ready", i+1, len(configs))
		case <-time.After(5 * time.Second):
			logger.Errorf("Timeout waiting for UDP listener %d to be ready", i+1)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("timeout waiting for UDP listener %d to be ready", i+1)
		}
	}
	close(udpReadyCh)

	// Start peer discovery for all P2P servers
	for i, config := range configs {
		go func(name string, server *p2p.Server) {
			if err := server.DiscoverPeers(); err != nil {
				logger.Errorf("Peer discovery failed for %s: %v", name, err)
			} else {
				logger.Infof("Peer discovery completed for %s", name)
			}
		}(config.Name, p2pServers[i])
	}

	// Start HTTP and WebSocket servers
	for i, config := range configs {
		startHTTPServer(config.Name, config.HTTPPort, messageChans[i], blockchains[i], readyCh, wg)
		startWebSocketServer(config.Name, config.WSPort, messageChans[i], rpcServers[i], readyCh, wg)
	}

	// Wait for HTTP and WebSocket servers to be ready
	logger.Infof("Waiting for %d servers to be ready", len(configs)*2) // HTTP and WS only
	for i := 0; i < len(configs)*2; i++ {
		select {
		case <-readyCh:
			logger.Infof("Server %d of %d ready", i+1, len(configs)*2)
		case <-time.After(10 * time.Second):
			logger.Errorf("Timeout waiting for server %d to be ready after 10s", i+1)
			// Cleanup resources before returning
			for i, db := range dbs {
				if db != nil {
					db.Close()
					dbs[i] = nil
				}
			}
			for i, srv := range tcpServers {
				if srv != nil {
					srv.Stop()
					tcpServers[i] = nil
				}
			}
			for i, srv := range p2pServers {
				if srv != nil && !closed[i] {
					srv.Close()
					closed[i] = true
					p2pServers[i] = nil
				}
			}
			return nil, fmt.Errorf("timeout waiting for server %d to be ready after 10s", i+1)
		}
	}
	logger.Infof("All servers are ready")

	resources := make([]NodeResources, len(configs))
	for i := range configs {
		resources[i] = NodeResources{
			Blockchain:      blockchains[i],
			MessageCh:       messageChans[i],
			RPCServer:       rpcServers[i],
			P2PServer:       p2pServers[i],
			PublicKey:       hex.EncodeToString(p2pServers[i].LocalNode().PublicKey),
			TCPServer:       tcpServers[i],
			WebSocketServer: wsServers[i],
			HTTPServer:      httpServers[i],
		}

		// FIX-P2P-05: wire P2P server as gossip broadcaster for block + tx propagation
		blockchains[i].SetGossipBroadcaster(p2pServers[i])
		logger.Infof("✅ Gossip broadcaster wired for %s", configs[i].Name)
	}

	return resources, nil
}
