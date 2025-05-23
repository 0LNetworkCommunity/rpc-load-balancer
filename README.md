# OpenLibra RPC Load Balancer Endpoint Manager

## Overview

The `update_endpoints.py` script is a sophisticated endpoint discovery and management tool for the OpenLibra network. It automatically discovers, validates, and configures RPC endpoints for nginx load balancing, ensuring optimal distribution of network traffic across healthy fullnodes while excluding problematic or unauthorized nodes.

## Key Features

### 1. Multi-Source Endpoint Discovery
The script discovers endpoints from three sources:

- **Local Configuration** (`endpoints.txt`): Manual list of known endpoints (optional)
- **Validator Universe**: Automatically discovers all validator IPs from on-chain data
- **Community Seed Peers**: Fetches curated endpoints from the [0LNetworkCommunity seed-peers repository](https://raw.githubusercontent.com/0LNetworkCommunity/seed-peers/refs/heads/main/fullnode_seed_playlist.json)

### 2. Intelligent Endpoint Validation
For each discovered endpoint, the script:

- ✅ Verifies the node is on the correct chain (chain_id = 1)
- ✅ Confirms the node role is "full_node" (excludes validator nodes)
- ✅ Checks the ledger version is within acceptable tolerance (default: ±500 blocks)
- ✅ Identifies archive nodes (oldest_block_height = 0)
- ✅ Tracks git hash versions for network consistency monitoring

### 3. VFN Security Filtering
The script implements critical security filtering:

- **Active Validator VFNs**: Allowed (these are Validator Full Nodes for active validators)
- **Inactive Validator VFNs**: Excluded (prevents routing through VFNs of non-validating nodes)
- **Regular Fullnodes**: Allowed (community-run nodes not associated with validators)

This prevents potential security issues where inactive validators could manipulate traffic through their VFNs.

## How It Works

### Step 1: Gather Validator Information
```python
# Queries the network for:
# - Complete validator universe (all registered validators)
# - Active validator set (currently validating)
# - Network addresses for each validator
```

### Step 2: Endpoint Discovery
```python
# Discovers endpoints from:
# 1. endpoints.txt (if exists)
# 2. GitHub seed-peers repository
# 3. All validator network/fullnode addresses
# Tests both HTTP and HTTPS on port 8080
```

### Step 3: Node Validation
Each endpoint is queried for node information:
```json
{
  "chain_id": 1,
  "node_role": "full_node",
  "ledger_version": "140051790",
  "oldest_block_height": "79347476",
  "block_height": "69995934",
  "git_hash": "750f39b5..."
}
```

### Step 4: Filtering and Classification
```
✓ KEEPING: http://172.104.211.8:8080/v1
  └─ Type: VFN (Validator Full Node)
  └─ Validator: 0xb8ba6c084fa504add5f23ae51e41f23d [ACTIVE]
  └─ Height: 69995934, Git: 750f39b5...

✗ EXCLUDING: http://37.27.83.253:8080/v1
  └─ Type: VFN (Validator Full Node)
  └─ Validator: 0xfdcf0ef094b962fb35997f4e2bcd4f27533b567bf8518f5b4f9400f47742be9b [INACTIVE]
  └─ Reason: VFN of inactive validator

✓ KEEPING: http://91.99.73.45:8080/v1
  └─ Type: Regular Fullnode (non-validator)
  └─ IP 91.99.73.45 not found in any validator network/fullnode config
  └─ Height: 69995934, Git: 750f39b5...
```

### Step 5: Nginx Configuration Update
The script updates the nginx upstream configuration with validated endpoints:
```nginx
upstream fullnodes {
    server 172.104.211.8:8080;
    server 70.15.242.6:8080;
    server 91.99.73.45:8080;
    # ... other validated endpoints
}
```

## Usage

```bash
# Update nginx configuration
python3 update_endpoints.py /etc/nginx/sites-available/rpc-load-balancer

# Test with a different config file
python3 update_endpoints.py /tmp/test-nginx.conf
```

## Configuration

Edit these constants at the top of the script:

```python
CHAIN_ID = 1              # OpenLibra mainnet chain ID
BALANCER_TOLERANCE = 500  # Max height difference from highest node
DEFAULT_RPC_PORT = 8080   # Default RPC port
QUERY_TIMEOUT = 1         # Timeout for endpoint queries (seconds)
```

### Timeout Considerations

The `QUERY_TIMEOUT` is set to 1 second by default to ensure quick discovery of responsive nodes. This helps when testing hundreds of potential endpoints. You may need to adjust this value based on your network conditions:

- **Fast/Local Network**: 1 second (default) works well
- **Slow/International Connections**: Consider 2-3 seconds
- **Debugging**: Increase to 5-10 seconds to diagnose connection issues

Note: With 200+ endpoints to test, each second of timeout can add significant time to the total runtime.

## Output Summary

The script provides comprehensive statistics:

```
=== Summary ===
Total IPs discovered from validators: 68
Total endpoints tested: 276
Valid fullnodes found: 45
Archive nodes found: 12
Endpoints within height tolerance: 42
Filtered 3 VFN endpoints from inactive validators
Final endpoint count for load balancer: 39

=== Git Hash Distribution ===
Git Hash                                      | Validators | Fullnodes
----------------------------------------------------------------------
750f39b5b91114754203d858ec6a758b2f664084     |          5 |        23
e402fe6d60b1fc0c2eecc51bc606c7200a579789     |          2 |        12
```

## Dependencies

- Python 3.6+
- `requests` library
- `utils/multiaddr.py` (included) for decoding validator network addresses

## Security Considerations

1. **VFN Filtering**: The script prevents routing through VFNs of inactive validators, which could be security risks
2. **Chain ID Verification**: Ensures nodes are on the correct network
3. **Node Role Check**: Excludes validator nodes from the load balancer pool
4. **Height Tolerance**: Ensures only synchronized nodes are included

## Network Benefits

This script helps the OpenLibra network by:

1. **Distributing Load**: Automatically discovers and includes all healthy fullnodes
2. **Improving Reliability**: Excludes out-of-sync or misconfigured nodes
3. **Enhancing Security**: Filters out potentially malicious VFNs
4. **Monitoring Health**: Tracks git versions and archive node availability
5. **Community Support**: Includes community-run fullnodes alongside validator infrastructure

## Contributing

To add new endpoints:

1. **Option 1**: Add to `endpoints.txt` in the same directory
2. **Option 2**: Submit a PR to the [seed-peers repository](https://github.com/0LNetworkCommunity/seed-peers)
3. **Option 3**: Run a validator and the script will auto-discover your endpoints

## Troubleshooting

- **"Wrong chain ID"**: Node is on testnet or different network
- **"Not a full_node"**: Node is running as validator, not suitable for public RPC
- **"index out of range"**: Validator has malformed network address (script handles gracefully)
- **Connection refused**: Endpoint is offline or firewall is blocking access

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions, troubleshooting, and manual configuration options.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/0LNetworkCommunity/rpc-load-balancer
cd rpc-load-balancer

# Install everything (nginx, Python deps, SSL certs)
sudo make install

# Set up automatic updates via cron
# Add to crontab: */15 * * * * cd ~/rpc-load-balancer && make cron
```

## Makefile Commands Reference

### Installation & Configuration
- `make install` - Complete installation (nginx, Python, SSL setup)
- `make rpc-load-balancer` - Generate nginx configuration

### Daily Operations
- `make update` - Discover endpoints and reload nginx
- `make cron` - Full cycle: pull → update → push
- `make cron-nogit` - Update without git operations

### Git Operations
- `make pull` - Pull latest changes
- `make push` - Commit and push changes

### Customization via Environment Variables
```bash
# Examples:
RPC_LB_DOMAIN=my-rpc.example.com make install
REPO_PATH=/opt/rpc-lb make update
```

See [INSTALL.md](INSTALL.md#environment-variables) for all available options.
