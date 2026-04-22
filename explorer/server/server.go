// MIT License
// Copyright (c) 2024 quantix-org

// Package server implements the block explorer HTTP server.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config holds explorer server configuration.
type Config struct {
	Addr    string
	RPCURL  string
	Network string
}

// Server is the block explorer HTTP server.
type Server struct {
	config *Config
	logger *slog.Logger
	rpc    *RPCClient
	server *http.Server
}

// New creates a new explorer server.
func New(config *Config, logger *slog.Logger) *Server {
	return &Server{
		config: config,
		logger: logger,
		rpc:    NewRPCClient(config.RPCURL),
	}
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/blocks", s.handleBlocks)
	mux.HandleFunc("/api/block/", s.handleBlock)
	mux.HandleFunc("/api/tx/", s.handleTransaction)
	mux.HandleFunc("/api/address/", s.handleAddress)
	mux.HandleFunc("/api/search", s.handleSearch)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/validators", s.handleValidators)

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Static files / SPA
	mux.HandleFunc("/", s.handleIndex)

	s.server = &http.Server{
		Addr:         s.config.Addr,
		Handler:      s.corsMiddleware(s.loggingMiddleware(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	return s.server.ListenAndServe()
}

// =====================================================
// API Handlers
// =====================================================

// handleBlocks returns a list of recent blocks.
func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	blocks, err := s.rpc.GetBlocks(limit, offset)
	if err != nil {
		s.jsonError(w, "Failed to fetch blocks: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, blocks, http.StatusOK)
}

// handleBlock returns a single block by hash or number.
func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/block/")
	if id == "" {
		s.jsonError(w, "Block ID required", http.StatusBadRequest)
		return
	}

	block, err := s.rpc.GetBlock(id)
	if err != nil {
		s.jsonError(w, "Block not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, block, http.StatusOK)
}

// handleTransaction returns a transaction by hash.
func (s *Server) handleTransaction(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimPrefix(r.URL.Path, "/api/tx/")
	if hash == "" {
		s.jsonError(w, "Transaction hash required", http.StatusBadRequest)
		return
	}

	tx, err := s.rpc.GetTransaction(hash)
	if err != nil {
		s.jsonError(w, "Transaction not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, tx, http.StatusOK)
}

// handleAddress returns address info and transactions.
func (s *Server) handleAddress(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimPrefix(r.URL.Path, "/api/address/")
	if addr == "" {
		s.jsonError(w, "Address required", http.StatusBadRequest)
		return
	}

	info, err := s.rpc.GetAddressInfo(addr)
	if err != nil {
		s.jsonError(w, "Address not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, info, http.StatusOK)
}

// handleSearch handles universal search (block, tx, address).
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		s.jsonError(w, "Search query required", http.StatusBadRequest)
		return
	}

	result := s.rpc.Search(query)
	s.jsonResponse(w, result, http.StatusOK)
}

// handleStats returns network statistics.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.rpc.GetStats()
	if err != nil {
		s.jsonError(w, "Failed to fetch stats", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, stats, http.StatusOK)
}

// handleValidators returns the current validator set.
func (s *Server) handleValidators(w http.ResponseWriter, r *http.Request) {
	validators, err := s.rpc.GetValidators()
	if err != nil {
		s.jsonError(w, "Failed to fetch validators", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, validators, http.StatusOK)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Serve the SPA
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(explorerHTML))
}

// =====================================================
// Helpers
// =====================================================

func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, message string, status int) {
	s.jsonResponse(w, map[string]string{"error": message}, status)
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
		)
	})
}

// =====================================================
// Explorer HTML (Single Page App)
// =====================================================

const explorerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantix Explorer</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⬡</text></svg>">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a25;
            --text-primary: #ffffff;
            --text-secondary: #8b8b9a;
            --accent: #00d4ff;
            --accent-dim: rgba(0, 212, 255, 0.1);
            --success: #00c853;
            --error: #ff5252;
            --border: rgba(255,255,255,0.08);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }

        /* Header */
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 24px;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 20px;
            font-weight: 700;
            color: var(--text-primary);
        }
        .logo-icon { font-size: 28px; }
        .search-box {
            flex: 1;
            max-width: 600px;
            position: relative;
        }
        .search-box input {
            width: 100%;
            padding: 12px 16px 12px 44px;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            transition: border-color 0.2s;
        }
        .search-box input:focus {
            outline: none;
            border-color: var(--accent);
        }
        .search-box::before {
            content: "🔍";
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 16px;
        }
        .network-badge {
            padding: 6px 12px;
            background: var(--accent-dim);
            border: 1px solid var(--accent);
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: var(--accent);
            text-transform: uppercase;
        }

        /* Main Content */
        main {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }
        .stat-label {
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 24px;
            font-weight: 700;
        }
        .stat-change {
            font-size: 12px;
            color: var(--success);
            margin-top: 4px;
        }

        /* Tables */
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .section-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .section-title {
            font-size: 16px;
            font-weight: 600;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 14px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: rgba(0,0,0,0.2);
        }
        tr:last-child td { border-bottom: none; }
        tr:hover { background: rgba(255,255,255,0.02); }

        /* Hash/Address styling */
        .hash {
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
            font-size: 13px;
        }
        .hash-short {
            max-width: 150px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge-success { background: rgba(0,200,83,0.15); color: var(--success); }
        .badge-pending { background: rgba(255,193,7,0.15); color: #ffc107; }
        .badge-error { background: rgba(255,82,82,0.15); color: var(--error); }

        /* Responsive */
        @media (max-width: 768px) {
            .header-content { flex-wrap: wrap; }
            .search-box { order: 3; max-width: none; width: 100%; margin-top: 16px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            th, td { padding: 12px; font-size: 13px; }
        }

        /* Loading */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 60px;
            color: var(--text-secondary);
        }
        .spinner {
            width: 24px;
            height: 24px;
            border: 2px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 12px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Detail Page */
        .detail-header {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
        }
        .detail-header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        .detail-grid {
            display: grid;
            grid-template-columns: 180px 1fr;
            gap: 1px;
            background: var(--border);
        }
        .detail-grid > div {
            padding: 14px 20px;
            background: var(--bg-card);
        }
        .detail-label {
            color: var(--text-secondary);
            font-size: 13px;
        }
        .detail-value {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 14px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <a href="/" class="logo">
                <span class="logo-icon">⬡</span>
                <span>Quantix Explorer</span>
            </a>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by address, tx hash, or block number...">
            </div>
            <div class="network-badge" id="networkBadge">Mainnet</div>
        </div>
    </header>

    <main id="app">
        <div class="loading">
            <div class="spinner"></div>
            Loading...
        </div>
    </main>

    <script>
        // Simple SPA Router
        const API = '/api';
        let currentView = 'home';

        // Fetch helpers
        async function fetchJSON(url) {
            const res = await fetch(url);
            if (!res.ok) throw new Error('Failed to fetch');
            return res.json();
        }

        function formatNumber(n) {
            return new Intl.NumberFormat().format(n);
        }

        function formatQTX(nqtx) {
            return (parseFloat(nqtx) / 1e18).toFixed(4) + ' QTX';
        }

        function shortHash(hash) {
            if (!hash || hash.length < 16) return hash;
            return hash.slice(0, 10) + '...' + hash.slice(-8);
        }

        function timeAgo(timestamp) {
            const seconds = Math.floor((Date.now() - new Date(timestamp)) / 1000);
            if (seconds < 60) return seconds + 's ago';
            if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
            if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
            return Math.floor(seconds / 86400) + 'd ago';
        }

        // Views
        async function renderHome() {
            const [stats, blocks] = await Promise.all([
                fetchJSON(API + '/stats'),
                fetchJSON(API + '/blocks?limit=10')
            ]);

            return ` + "`" + `
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Block Height</div>
                        <div class="stat-value">${formatNumber(stats.block_height)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Transactions</div>
                        <div class="stat-value">${formatNumber(stats.total_transactions)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Validators</div>
                        <div class="stat-value">${stats.validator_count}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Total Staked</div>
                        <div class="stat-value">${formatQTX(stats.total_staked)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Avg Block Time</div>
                        <div class="stat-value">${stats.avg_block_time}s</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">TPS (24h)</div>
                        <div class="stat-value">${stats.tps_24h}</div>
                    </div>
                </div>

                <div class="section">
                    <div class="section-header">
                        <span class="section-title">Latest Blocks</span>
                        <a href="#/blocks">View all →</a>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>Block</th>
                                <th>Age</th>
                                <th>Txns</th>
                                <th>Validator</th>
                                <th>Gas Used</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${blocks.map(b => ` + "`" + `
                                <tr>
                                    <td><a href="#/block/${b.number}">${formatNumber(b.number)}</a></td>
                                    <td>${timeAgo(b.timestamp)}</td>
                                    <td>${b.tx_count}</td>
                                    <td class="hash hash-short"><a href="#/address/${b.validator}">${shortHash(b.validator)}</a></td>
                                    <td>${formatNumber(b.gas_used)}</td>
                                </tr>
                            ` + "`" + `).join('')}
                        </tbody>
                    </table>
                </div>
            ` + "`" + `;
        }

        async function renderBlock(id) {
            const block = await fetchJSON(API + '/block/' + id);
            return ` + "`" + `
                <div class="detail-header">
                    <h1>Block #${formatNumber(block.number)}</h1>
                    <span class="badge badge-success">Finalized</span>
                </div>
                <div class="section">
                    <div class="detail-grid">
                        <div class="detail-label">Block Hash</div>
                        <div class="detail-value">${block.hash}</div>
                        <div class="detail-label">Parent Hash</div>
                        <div class="detail-value"><a href="#/block/${block.parent_hash}">${block.parent_hash}</a></div>
                        <div class="detail-label">Timestamp</div>
                        <div class="detail-value">${new Date(block.timestamp).toLocaleString()} (${timeAgo(block.timestamp)})</div>
                        <div class="detail-label">Validator</div>
                        <div class="detail-value"><a href="#/address/${block.validator}">${block.validator}</a></div>
                        <div class="detail-label">Transactions</div>
                        <div class="detail-value">${block.tx_count}</div>
                        <div class="detail-label">Gas Used</div>
                        <div class="detail-value">${formatNumber(block.gas_used)} / ${formatNumber(block.gas_limit)}</div>
                        <div class="detail-label">State Root</div>
                        <div class="detail-value">${block.state_root}</div>
                    </div>
                </div>
            ` + "`" + `;
        }

        async function renderTx(hash) {
            const tx = await fetchJSON(API + '/tx/' + hash);
            return ` + "`" + `
                <div class="detail-header">
                    <h1>Transaction</h1>
                    <span class="badge badge-success">${tx.status}</span>
                </div>
                <div class="section">
                    <div class="detail-grid">
                        <div class="detail-label">Transaction Hash</div>
                        <div class="detail-value">${tx.hash}</div>
                        <div class="detail-label">Block</div>
                        <div class="detail-value"><a href="#/block/${tx.block_number}">${formatNumber(tx.block_number)}</a></div>
                        <div class="detail-label">From</div>
                        <div class="detail-value"><a href="#/address/${tx.from}">${tx.from}</a></div>
                        <div class="detail-label">To</div>
                        <div class="detail-value"><a href="#/address/${tx.to}">${tx.to}</a></div>
                        <div class="detail-label">Value</div>
                        <div class="detail-value">${formatQTX(tx.value)}</div>
                        <div class="detail-label">Gas Used</div>
                        <div class="detail-value">${formatNumber(tx.gas_used)}</div>
                        <div class="detail-label">Gas Price</div>
                        <div class="detail-value">${tx.gas_price} nQTX</div>
                        <div class="detail-label">Nonce</div>
                        <div class="detail-value">${tx.nonce}</div>
                    </div>
                </div>
            ` + "`" + `;
        }

        async function renderAddress(addr) {
            const info = await fetchJSON(API + '/address/' + addr);
            return ` + "`" + `
                <div class="detail-header">
                    <h1>Address</h1>
                    ${info.is_validator ? '<span class="badge badge-success">Validator</span>' : ''}
                    ${info.is_contract ? '<span class="badge badge-pending">Contract</span>' : ''}
                </div>
                <div class="section">
                    <div class="detail-grid">
                        <div class="detail-label">Address</div>
                        <div class="detail-value">${info.address}</div>
                        <div class="detail-label">Balance</div>
                        <div class="detail-value">${formatQTX(info.balance)}</div>
                        <div class="detail-label">Transactions</div>
                        <div class="detail-value">${formatNumber(info.tx_count)}</div>
                        ${info.is_validator ? ` + "`" + `
                            <div class="detail-label">Staked</div>
                            <div class="detail-value">${formatQTX(info.staked)}</div>
                        ` + "`" + ` : ''}
                    </div>
                </div>
            ` + "`" + `;
        }

        // Router
        async function route() {
            const hash = window.location.hash.slice(1) || '/';
            const app = document.getElementById('app');
            
            app.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
            
            try {
                let html;
                if (hash === '/' || hash === '') {
                    html = await renderHome();
                } else if (hash.startsWith('/block/')) {
                    html = await renderBlock(hash.slice(7));
                } else if (hash.startsWith('/tx/')) {
                    html = await renderTx(hash.slice(4));
                } else if (hash.startsWith('/address/')) {
                    html = await renderAddress(hash.slice(9));
                } else {
                    html = '<div class="loading">Page not found</div>';
                }
                app.innerHTML = html;
            } catch (err) {
                app.innerHTML = '<div class="loading">Error loading data</div>';
                console.error(err);
            }
        }

        // Search
        document.getElementById('searchInput').addEventListener('keypress', async (e) => {
            if (e.key === 'Enter') {
                const q = e.target.value.trim();
                if (!q) return;
                
                try {
                    const result = await fetchJSON(API + '/search?q=' + encodeURIComponent(q));
                    if (result.type === 'block') {
                        window.location.hash = '/block/' + result.id;
                    } else if (result.type === 'tx') {
                        window.location.hash = '/tx/' + result.id;
                    } else if (result.type === 'address') {
                        window.location.hash = '/address/' + result.id;
                    } else {
                        alert('No results found');
                    }
                } catch {
                    alert('Search failed');
                }
            }
        });

        // Init
        window.addEventListener('hashchange', route);
        route();
    </script>
</body>
</html>` + "`"
