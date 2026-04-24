# Quantix Blockchain Run Guide

Here is a complete and comprehensive guide to running the Quantix Blockchain, either locally (Single Node) or as a full consensus network (4-Node PBFT Cluster).

---

## 🛠️ Step 1: Prerequisites

Ensure your system has the following installed:

1. **Go (Golang)** version 1.24 or newer.
2. **Docker & Docker Compose** (Optional, if you wish to run via containers).

---

## 🏗️ Step 2: Build Binary from Source Code

Before running a node, you need to compile the source code into an executable binary.

Open your terminal and run:

```bash
# Navigate to the project directory
cd /Users/[username]/Developer/quantix

# Build the binary
go build -o bin/quantix ./src/cli/main.go
```

If successful, the `quantix` binary file will be located inside the `bin/` folder.

---

## 🚀 Step 3: Run Quantix (Choose an Option)

Quantix can run in 2 main modes: **Devnet (Single Node)** or **PBFT Cluster (Minimum 4 Nodes)**.

### Option A: Running a Single Node (Solo/Devnet Mode)

This mode is perfect for development and testing. The node will automatically mine roughly every 8 seconds without waiting for PBFT consensus from other nodes.

**Manual Method (via CLI):**

```bash
./bin/quantix \
  -nodes 1 \
  -node-index 0 \
  -roles validator \
  -datadir data/devnode \
  -http-port 0.0.0.0:8560 \
  -udp-port 32307 \
  -tcp-addr 0.0.0.0:32307 \
  -dev-mode
```

**Script Method:**
You can also use the automated script using Docker:

```bash
./scripts/start-devnet.sh
```

### Option B: Running Full PBFT Consensus (4-Node Cluster)

Because Quantix uses _Practical Byzantine Fault Tolerance_ (PBFT), network consensus requires a minimum of 4 validators to be active.

**Fastest Method (via Local Integration Script):**
This script builds the binary, runs 4 nodes concurrently in the terminal, and submits several test transactions:

```bash
./scripts/test-4node.sh
```

**Docker Compose Method (Testnet Simulation):**
For a cleaner testnet simulation using background containers:

```bash
# Run 4 validator nodes + monitoring
./scripts/start-testnet.sh
```

_Note: The HTTP ports for the nodes will be `8560`, `8561`, `8562`, and `8563`._

---

## 🔍 Step 4: Verify and Interact with the Node

Once the node is running (e.g., Option A on port 8560), you can check the network status using the built-in REST API.

Open a new terminal and try the following `curl` commands:

**1. Check current block count:**

```bash
curl -s http://localhost:8560/blockcount
# Example output: {"count":10}
```

**2. Check Best Block Hash:**

```bash
curl -s http://localhost:8560/bestblockhash
```

**3. View specific Block details (Replace ID with number: 0, 1, 2, etc.):**

```bash
curl -s http://localhost:8560/block/1
```

**4. Check Network Health of all nodes (If using PBFT):**

```bash
./scripts/check-health.sh
```

---

## 🧽 Step 5: Stop and Reset Data (Clean Up)

**If running via CLI / `test-4node.sh`:**
Press `CTRL + C` in the terminal inside Quantix to stop the process (graceful shutdown).

**If running via Docker (start-devnet / start-testnet):**

```bash
# Stop services and remove previous chain data
./scripts/reset.sh
```

_Note: Running `reset.sh` will delete the `data/` folder, resetting the blocks back to Genesis (Block 0) upon restart._
