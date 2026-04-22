// MIT License
// Copyright (c) 2024 quantix-org

// Package faucet provides a testnet/devnet QTX faucet service.
package faucet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// =====================================================
// Faucet Configuration
// =====================================================

// Config holds faucet configuration.
type Config struct {
	// Amount of QTX to dispense per request (in nQTX)
	Amount uint64 `json:"amount"`

	// Cooldown between requests from same address
	Cooldown time.Duration `json:"cooldown"`

	// Cooldown between requests from same IP
	IPCooldown time.Duration `json:"ip_cooldown"`

	// Maximum requests per day per address
	MaxDailyRequests int `json:"max_daily_requests"`

	// RPC endpoint for sending transactions
	RPCEndpoint string `json:"rpc_endpoint"`

	// Faucet wallet address
	FaucetAddress string `json:"faucet_address"`

	// Faucet private key (encrypted)
	FaucetKey string `json:"faucet_key"`

	// HTTP server address
	ListenAddr string `json:"listen_addr"`

	// Enable rate limiting
	RateLimitEnabled bool `json:"rate_limit_enabled"`

	// Enable CAPTCHA
	CaptchaEnabled bool `json:"captcha_enabled"`
	CaptchaSecret  string `json:"captcha_secret"`
}

// DefaultConfig returns the default faucet configuration.
func DefaultConfig() *Config {
	return &Config{
		Amount:           1000000000000000000, // 1 QTX
		Cooldown:         24 * time.Hour,
		IPCooldown:       1 * time.Hour,
		MaxDailyRequests: 3,
		RPCEndpoint:      "http://localhost:8545",
		ListenAddr:       ":8080",
		RateLimitEnabled: true,
		CaptchaEnabled:   false,
	}
}

// =====================================================
// Faucet Service
// =====================================================

// Faucet is the testnet faucet service.
type Faucet struct {
	config *Config
	logger *slog.Logger

	// Request tracking
	mu              sync.RWMutex
	addressRequests map[string][]time.Time
	ipRequests      map[string][]time.Time

	// Statistics
	totalDispensed uint64
	totalRequests  int64
	successCount   int64
	failureCount   int64

	// HTTP server
	server *http.Server
}

// New creates a new faucet instance.
func New(config *Config, logger *slog.Logger) *Faucet {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Faucet{
		config:          config,
		logger:          logger,
		addressRequests: make(map[string][]time.Time),
		ipRequests:      make(map[string][]time.Time),
	}
}

// Start starts the faucet HTTP server.
func (f *Faucet) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/faucet", f.handleFaucetRequest)
	mux.HandleFunc("/api/status", f.handleStatus)
	mux.HandleFunc("/api/info", f.handleInfo)

	// Health check
	mux.HandleFunc("/health", f.handleHealth)

	// Static files (if any)
	mux.HandleFunc("/", f.handleIndex)

	f.server = &http.Server{
		Addr:         f.config.ListenAddr,
		Handler:      f.corsMiddleware(f.loggingMiddleware(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	f.logger.Info("Starting faucet server", "addr", f.config.ListenAddr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f.server.Shutdown(shutdownCtx)
	}()

	return f.server.ListenAndServe()
}

// =====================================================
// HTTP Handlers
// =====================================================

// FaucetRequest is the request body for faucet requests.
type FaucetRequest struct {
	Address string `json:"address"`
	Captcha string `json:"captcha,omitempty"`
}

// FaucetResponse is the response for faucet requests.
type FaucetResponse struct {
	Success bool   `json:"success"`
	TxHash  string `json:"tx_hash,omitempty"`
	Amount  string `json:"amount,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (f *Faucet) handleFaucetRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		f.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req FaucetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate address
	if !isValidQuantixAddress(req.Address) {
		f.jsonError(w, "Invalid Quantix address", http.StatusBadRequest)
		return
	}

	// Get client IP
	clientIP := getClientIP(r)

	// Check rate limits
	if f.config.RateLimitEnabled {
		if err := f.checkRateLimits(req.Address, clientIP); err != nil {
			f.jsonError(w, err.Error(), http.StatusTooManyRequests)
			return
		}
	}

	// Verify CAPTCHA if enabled
	if f.config.CaptchaEnabled {
		if !f.verifyCaptcha(req.Captcha) {
			f.jsonError(w, "Invalid CAPTCHA", http.StatusBadRequest)
			return
		}
	}

	// Send tokens
	txHash, err := f.sendTokens(req.Address)
	if err != nil {
		f.logger.Error("Failed to send tokens", "address", req.Address, "error", err)
		f.failureCount++
		f.jsonError(w, "Failed to send tokens: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Record request
	f.recordRequest(req.Address, clientIP)

	// Update stats
	f.totalDispensed += f.config.Amount
	f.totalRequests++
	f.successCount++

	// Return success
	resp := FaucetResponse{
		Success: true,
		TxHash:  txHash,
		Amount:  formatQTX(f.config.Amount),
		Message: fmt.Sprintf("Sent %s to %s", formatQTX(f.config.Amount), req.Address),
	}

	f.jsonResponse(w, resp, http.StatusOK)
}

func (f *Faucet) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"online":           true,
		"total_dispensed":  formatQTX(f.totalDispensed),
		"total_requests":   f.totalRequests,
		"success_count":    f.successCount,
		"failure_count":    f.failureCount,
		"amount_per_request": formatQTX(f.config.Amount),
		"cooldown_hours":   f.config.Cooldown.Hours(),
	}

	f.jsonResponse(w, status, http.StatusOK)
}

func (f *Faucet) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"network":            "testnet",
		"faucet_address":     f.config.FaucetAddress,
		"amount_per_request": formatQTX(f.config.Amount),
		"cooldown":           f.config.Cooldown.String(),
		"max_daily_requests": f.config.MaxDailyRequests,
		"captcha_required":   f.config.CaptchaEnabled,
	}

	f.jsonResponse(w, info, http.StatusOK)
}

func (f *Faucet) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func (f *Faucet) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(faucetHTML))
}

// =====================================================
// Rate Limiting
// =====================================================

func (f *Faucet) checkRateLimits(address, ip string) error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	now := time.Now()

	// Check address cooldown
	if requests, ok := f.addressRequests[address]; ok {
		// Count requests in last 24 hours
		recentCount := 0
		for _, t := range requests {
			if now.Sub(t) < 24*time.Hour {
				recentCount++
			}
		}

		if recentCount >= f.config.MaxDailyRequests {
			return errors.New("daily request limit reached for this address")
		}

		// Check cooldown
		if len(requests) > 0 {
			lastRequest := requests[len(requests)-1]
			if now.Sub(lastRequest) < f.config.Cooldown {
				remaining := f.config.Cooldown - now.Sub(lastRequest)
				return fmt.Errorf("please wait %s before requesting again", remaining.Round(time.Minute))
			}
		}
	}

	// Check IP cooldown
	if requests, ok := f.ipRequests[ip]; ok {
		if len(requests) > 0 {
			lastRequest := requests[len(requests)-1]
			if now.Sub(lastRequest) < f.config.IPCooldown {
				remaining := f.config.IPCooldown - now.Sub(lastRequest)
				return fmt.Errorf("please wait %s before requesting again from this IP", remaining.Round(time.Minute))
			}
		}
	}

	return nil
}

func (f *Faucet) recordRequest(address, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()

	// Record address request
	f.addressRequests[address] = append(f.addressRequests[address], now)

	// Record IP request
	f.ipRequests[ip] = append(f.ipRequests[ip], now)

	// Cleanup old entries (keep last 24 hours)
	f.cleanupOldRequests()
}

func (f *Faucet) cleanupOldRequests() {
	cutoff := time.Now().Add(-24 * time.Hour)

	for addr, requests := range f.addressRequests {
		var recent []time.Time
		for _, t := range requests {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(f.addressRequests, addr)
		} else {
			f.addressRequests[addr] = recent
		}
	}

	for ip, requests := range f.ipRequests {
		var recent []time.Time
		for _, t := range requests {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(f.ipRequests, ip)
		} else {
			f.ipRequests[ip] = recent
		}
	}
}

// =====================================================
// Token Sending
// =====================================================

func (f *Faucet) sendTokens(address string) (string, error) {
	// TODO: Implement actual token sending via RPC
	// For now, return a mock transaction hash
	
	// This would typically:
	// 1. Create a transaction from faucet address to recipient
	// 2. Sign with faucet private key (SPHINCS+)
	// 3. Submit via JSON-RPC
	// 4. Return transaction hash

	mockTxHash := fmt.Sprintf("0x%x", time.Now().UnixNano())
	
	f.logger.Info("Tokens sent",
		"to", address,
		"amount", formatQTX(f.config.Amount),
		"tx_hash", mockTxHash,
	)

	return mockTxHash, nil
}

// =====================================================
// Helpers
// =====================================================

func (f *Faucet) verifyCaptcha(token string) bool {
	// TODO: Implement actual CAPTCHA verification
	return token != ""
}

func (f *Faucet) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (f *Faucet) jsonError(w http.ResponseWriter, message string, status int) {
	resp := FaucetResponse{
		Success: false,
		Error:   message,
	}
	f.jsonResponse(w, resp, status)
}

func (f *Faucet) corsMiddleware(next http.Handler) http.Handler {
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

func (f *Faucet) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		f.logger.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"ip", getClientIP(r),
			"duration", time.Since(start),
		)
	})
}

func isValidQuantixAddress(address string) bool {
	// Quantix addresses start with "qtx1" and are 42 characters (Bech32)
	if len(address) != 42 {
		return false
	}
	if address[:4] != "qtx1" {
		return false
	}
	return true
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func formatQTX(amount uint64) string {
	qtx := float64(amount) / 1e18
	return fmt.Sprintf("%.6f QTX", qtx)
}

// =====================================================
// Faucet Web UI
// =====================================================

const faucetHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantix Testnet Faucet</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            padding: 40px;
            max-width: 500px;
            width: 90%;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        h1 { 
            text-align: center; 
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }
        .form-group { margin-bottom: 20px; }
        label { 
            display: block; 
            margin-bottom: 8px;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 14px;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            background: rgba(255,255,255,0.05);
            color: #fff;
            font-size: 14px;
            font-family: monospace;
        }
        input:focus {
            outline: none;
            border-color: #00d4ff;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #00d4ff 0%, #0099ff 100%);
            border: none;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover { transform: translateY(-2px); }
        button:disabled { 
            opacity: 0.5; 
            cursor: not-allowed;
            transform: none;
        }
        .message {
            margin-top: 20px;
            padding: 14px;
            border-radius: 8px;
            text-align: center;
        }
        .success { background: rgba(0,200,83,0.2); border: 1px solid rgba(0,200,83,0.3); }
        .error { background: rgba(255,82,82,0.2); border: 1px solid rgba(255,82,82,0.3); }
        .info {
            margin-top: 30px;
            padding: 20px;
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚰 Quantix Faucet</h1>
        <p class="subtitle">Get testnet QTX tokens</p>
        
        <form id="faucetForm">
            <div class="form-group">
                <label for="address">Quantix Address</label>
                <input type="text" id="address" placeholder="qtx1..." required>
            </div>
            <button type="submit" id="submitBtn">Request Tokens</button>
        </form>
        
        <div id="message" class="message" style="display:none;"></div>
        
        <div class="info">
            <div class="info-row">
                <span class="info-label">Amount per request</span>
                <span>1.0 QTX</span>
            </div>
            <div class="info-row">
                <span class="info-label">Cooldown</span>
                <span>24 hours</span>
            </div>
            <div class="info-row">
                <span class="info-label">Network</span>
                <span>Testnet</span>
            </div>
        </div>
    </div>
    
    <script>
        document.getElementById('faucetForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const msg = document.getElementById('message');
            const address = document.getElementById('address').value;
            
            btn.disabled = true;
            btn.textContent = 'Sending...';
            msg.style.display = 'none';
            
            try {
                const res = await fetch('/api/faucet', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address })
                });
                const data = await res.json();
                
                msg.style.display = 'block';
                if (data.success) {
                    msg.className = 'message success';
                    msg.innerHTML = '✅ ' + data.message + '<br><small>TX: ' + data.tx_hash + '</small>';
                } else {
                    msg.className = 'message error';
                    msg.textContent = '❌ ' + data.error;
                }
            } catch (err) {
                msg.style.display = 'block';
                msg.className = 'message error';
                msg.textContent = '❌ Network error. Please try again.';
            }
            
            btn.disabled = false;
            btn.textContent = 'Request Tokens';
        });
    </script>
</body>
</html>`
