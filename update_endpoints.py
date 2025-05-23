import sys
import requests
from utils.multiaddr import decode_multiaddr_simple
from collections import defaultdict
import json

# Constants
CHAIN_ID = 1  # OpenLibra chain ID
BALANCER_TOLERANCE = 500  # Height tolerance for load balancing
DEFAULT_RPC_PORT = 8080  # Default port for RPC endpoints
QUERY_TIMEOUT = 1  # Timeout for RPC queries (seconds) - reduced for faster discovery
SEED_PEERS_URL = "https://raw.githubusercontent.com/0LNetworkCommunity/seed-peers/refs/heads/main/fullnode_seed_playlist.json"

# nginx_config = "/etc/nginx/sites-available/rpc-load-balancer"
nginx_config = sys.argv[1]

# Read endpoints from the adjacent file (if exists, for backwards compatibility)
try:
    with open("endpoints.txt", "r") as f:
        manual_endpoints = [
            line.strip() for line in f.readlines() if not line.startswith("#")
        ]
except FileNotFoundError:
    manual_endpoints = []
    print("No endpoints.txt file found, will discover endpoints from multiple sources")


# Fetch endpoints from seed-peers repository
def fetch_seed_peers():
    """Fetch endpoints from the 0LNetworkCommunity seed-peers repository"""
    seed_endpoints = []
    try:
        print("Fetching endpoints from seed-peers repository...")
        response = requests.get(SEED_PEERS_URL, timeout=10)
        response.raise_for_status()
        data = response.json()

        for node in data.get("nodes", []):
            url = node.get("url", "")
            note = node.get("note", "unknown")
            if url:
                seed_endpoints.append(url)
                print(f"  └─ Added seed peer: {url} (note: {note})")

        print(f"Fetched {len(seed_endpoints)} endpoints from seed-peers repository")
    except Exception as e:
        print(f"Error fetching seed-peers: {e}")

    return seed_endpoints


# Base URL for querying network resources
BASE_URL = "https://rpc.openlibra.space:8080"


# Function to get validator universe and active validator set
def get_validator_info():
    """Get validator universe and active validator set from 0x1 resources"""
    try:
        response = requests.get(f"{BASE_URL}/v1/accounts/0x1/resources", timeout=10)
        response.raise_for_status()
        resources = response.json()

        validator_universe = []
        active_validators = []

        for resource in resources:
            if resource["type"] == "0x1::validator_universe::ValidatorUniverse":
                validator_universe = resource["data"]["validators"]
            elif resource["type"] == "0x1::stake::ValidatorSet":
                active_validators = [
                    v["addr"] for v in resource["data"]["active_validators"]
                ]

        return validator_universe, active_validators
    except Exception as e:
        print(f"Error fetching validator info: {e}")
        return [], []


# Function to extract IP from multiaddr hex with better error handling
def extract_ip_from_multiaddr(hex_string):
    """Extract IP address from multiaddr hex, handling edge cases"""
    try:
        # Remove 0x prefix if present
        hex_string = hex_string.replace("0x", "")

        # Convert hex to bytes
        bytes_data = bytes.fromhex(hex_string)

        # Check if we have enough bytes for IP (need at least 8 bytes)
        if len(bytes_data) >= 8:
            # Extract IP address (bytes 4-7)
            ip = f"{bytes_data[4]}.{bytes_data[5]}.{bytes_data[6]}.{bytes_data[7]}"
            return ip
    except Exception as e:
        # Silently fail, will be handled by caller
        pass

    return None


# Function to get validator resources and extract IP addresses
def get_validator_ips(validator_addr):
    """Get IP addresses from validator's network addresses"""
    ips = []
    try:
        response = requests.get(
            f"{BASE_URL}/v1/accounts/{validator_addr}/resources", timeout=10
        )
        response.raise_for_status()
        resources = response.json()

        for resource in resources:
            if resource["type"] == "0x1::stake::ValidatorConfig":
                # Get network addresses from validator config
                network_addresses = resource["data"].get("network_addresses", "")
                if network_addresses and network_addresses != "0x00":
                    # First try the simple extraction method
                    ip = extract_ip_from_multiaddr(network_addresses)
                    if ip:
                        ips.append(ip)
                    else:
                        # If that fails, try the full decode
                        try:
                            decoded = decode_multiaddr_simple(network_addresses)
                            # Extract IPv4 addresses from the decoded multiaddr string
                            parts = decoded.split("/")
                            for i, part in enumerate(parts):
                                if part == "ip4" and i + 1 < len(parts):
                                    ips.append(parts[i + 1])
                        except Exception as e:
                            print(
                                f"  └─ Note: Could not fully decode network_addresses for {validator_addr}: {e}"
                            )

                # Also check fullnode addresses
                fullnode_addresses = resource["data"].get("fullnode_addresses", "")
                if fullnode_addresses and fullnode_addresses != "0x00":
                    # First try the simple extraction method
                    ip = extract_ip_from_multiaddr(fullnode_addresses)
                    if ip:
                        ips.append(ip)
                    else:
                        # If that fails, try the full decode
                        try:
                            decoded = decode_multiaddr_simple(fullnode_addresses)
                            parts = decoded.split("/")
                            for i, part in enumerate(parts):
                                if part == "ip4" and i + 1 < len(parts):
                                    ips.append(parts[i + 1])
                        except Exception as e:
                            print(
                                f"  └─ Note: Could not fully decode fullnode_addresses for {validator_addr}: {e}"
                            )
                elif fullnode_addresses == "0x00":
                    print(
                        f"  └─ Note: Validator {validator_addr} has invalid fullnode_addresses (0x00)"
                    )
    except Exception as e:
        print(f"Error fetching resources for validator {validator_addr}: {e}")

    return ips


# Function to extract IP from endpoint URL
def extract_ip_from_endpoint(endpoint):
    """Extract IP address from endpoint URL"""
    try:
        # Remove protocol and path
        url_parts = endpoint.split("//")
        if len(url_parts) > 1:
            host_part = url_parts[1].split("/")[0]
            # Remove port if present
            ip = host_part.split(":")[0]
            return ip
    except:
        pass
    return None


# Function to query node info from an endpoint
def query_node_info(endpoint):
    """Query node information from an RPC endpoint"""
    try:
        response = requests.get(endpoint, timeout=QUERY_TIMEOUT)
        data = response.json()

        # Extract relevant fields
        node_info = {
            "chain_id": data.get("chain_id"),
            "epoch": data.get("epoch"),
            "ledger_version": int(data.get("ledger_version", 0)),
            "oldest_block_height": int(data.get("oldest_block_height", -1)),
            "block_height": int(data.get("block_height", 0)),
            "node_role": data.get("node_role", "unknown"),
            "git_hash": data.get("git_hash", "unknown"),
            "ledger_timestamp": data.get("ledger_timestamp", "0"),
        }

        return node_info
    except Exception as e:
        return None


# Get validator universe and active validator set
print("Fetching validator universe and active validator set...")
validator_universe, active_validators = get_validator_info()
print(
    f"Found {len(validator_universe)} validators in universe, {len(active_validators)} active"
)

# Build a map of IPs to validator addresses
ip_to_validator = {}
validator_to_active = {v: v in active_validators for v in validator_universe}
all_validator_ips = set()  # Track all validator IPs for reporting

print("\nFetching validator network addresses...")
for validator in validator_universe:
    ips = get_validator_ips(validator)
    for ip in ips:
        ip_to_validator[ip] = validator
        all_validator_ips.add(ip)
    if ips:
        print(f"✓ Validator {validator}: IPs {ips}")

# Build list of endpoints to test (manual + discovered + seed-peers)
endpoints_to_test = set(manual_endpoints)

# Add endpoints from seed-peers repository
seed_endpoints = fetch_seed_peers()
endpoints_to_test.update(seed_endpoints)

# Add discovered validator IPs as potential endpoints
print(f"\nDiscovered {len(all_validator_ips)} unique IPs from validator configs")
for ip in all_validator_ips:
    # Try both HTTP and HTTPS
    endpoints_to_test.add(f"http://{ip}:{DEFAULT_RPC_PORT}/v1/")
    endpoints_to_test.add(f"https://{ip}:{DEFAULT_RPC_PORT}/v1/")

print(f"\nTotal endpoints to test from all sources:")
print(f"  • Manual (endpoints.txt): {len(manual_endpoints)}")
print(f"  • Seed peers repository: {len(seed_endpoints)}")
print(f"  • Validator discovery: {len(all_validator_ips) * 2} (HTTP + HTTPS)")
print(f"  • Total unique endpoints: {len(endpoints_to_test)}")

# Query all endpoints and collect node information
print("\nQuerying endpoints for node information...")
valid_nodes = {}
git_hash_stats = defaultdict(lambda: {"validators": 0, "fullnodes": 0})
archive_nodes = []

for endpoint in endpoints_to_test:
    node_info = query_node_info(endpoint)

    if node_info:
        # Check chain ID
        if node_info["chain_id"] != CHAIN_ID:
            print(
                f"✗ {endpoint}: Wrong chain ID ({node_info['chain_id']} != {CHAIN_ID})"
            )
            continue

        # Check node role
        if node_info["node_role"] != "full_node":
            print(f"✗ {endpoint}: Not a full_node (role: {node_info['node_role']})")
            # Still count for statistics
            if node_info["node_role"] == "validator":
                git_hash_stats[node_info["git_hash"]]["validators"] += 1
            continue

        # Valid fullnode
        valid_nodes[endpoint] = node_info
        git_hash_stats[node_info["git_hash"]]["fullnodes"] += 1

        # Check if it's an archive node
        is_archive = node_info["oldest_block_height"] == 0
        if is_archive:
            archive_nodes.append(endpoint)

        print(
            f"✓ {endpoint}: Valid fullnode, height {node_info['block_height']}, "
            + f"ledger {node_info['ledger_version']}"
            + (f" [ARCHIVE NODE]" if is_archive else "")
        )

print(f"\nFound {len(valid_nodes)} valid fullnodes")

# Find the highest ledger_version
if not valid_nodes:
    print("No valid fullnode endpoints found!")
    sys.exit(1)

max_version = max(node["ledger_version"] for node in valid_nodes.values())

# Filter nodes within tolerance of the highest ledger_version
top_endpoints = [
    endpoint
    for endpoint, node in valid_nodes.items()
    if (max_version - BALANCER_TOLERANCE)
    <= node["ledger_version"]
    <= (max_version + BALANCER_TOLERANCE)
]

print(f"\n{len(top_endpoints)} endpoints within tolerance of max height {max_version}")

# Filter out VFN endpoints from validators not in active set
filtered_endpoints = []
print("\n=== Endpoint Classification ===")
for endpoint in top_endpoints:
    ip = extract_ip_from_endpoint(endpoint)
    node_info = valid_nodes[endpoint]

    if ip and ip in ip_to_validator:
        validator = ip_to_validator[ip]
        if validator_to_active.get(validator, False):
            # Validator is active, keep the endpoint
            filtered_endpoints.append(endpoint)
            print(f"✓ KEEPING: {endpoint}")
            print(f"  └─ Type: VFN (Validator Full Node)")
            print(f"  └─ Validator: {validator} [ACTIVE]")
            print(
                f"  └─ Height: {node_info['block_height']}, Git: {node_info['git_hash'][:8]}..."
            )
        else:
            # Validator is not active, this is a VFN we should exclude
            print(f"✗ EXCLUDING: {endpoint}")
            print(f"  └─ Type: VFN (Validator Full Node)")
            print(f"  └─ Validator: {validator} [INACTIVE]")
            print(f"  └─ Reason: VFN of inactive validator")
    else:
        # Not a VFN endpoint or couldn't determine, keep it
        filtered_endpoints.append(endpoint)
        print(f"✓ KEEPING: {endpoint}")
        print(f"  └─ Type: Regular Fullnode (non-validator)")
        if ip:
            print(f"  └─ IP {ip} not found in any validator network/fullnode config")
        else:
            print(f"  └─ Could not extract IP from endpoint")
        print(
            f"  └─ Height: {node_info['block_height']}, Git: {node_info['git_hash'][:8]}..."
        )

# Summary statistics
print(f"\n=== Summary ===")
print(f"Total IPs discovered from validators: {len(all_validator_ips)}")
print(f"Total endpoints tested: {len(endpoints_to_test)}")
print(f"Valid fullnodes found: {len(valid_nodes)}")
print(f"Archive nodes found: {len(archive_nodes)}")
print(f"Endpoints within height tolerance: {len(top_endpoints)}")
print(
    f"Filtered {len(top_endpoints) - len(filtered_endpoints)} VFN endpoints from inactive validators"
)
print(f"Final endpoint count for load balancer: {len(filtered_endpoints)}")

# Git hash summary
print(f"\n=== Git Hash Distribution ===")
print(f"{'Git Hash':<45} | {'Validators':>10} | {'Fullnodes':>10}")
print("-" * 70)
for git_hash, counts in sorted(git_hash_stats.items()):
    print(f"{git_hash:<45} | {counts['validators']:>10} | {counts['fullnodes']:>10}")

# Update Nginx configuration
with open(nginx_config, "r") as f:
    content = f.readlines()

# Identify the lines to replace
start_index = content.index("upstream fullnodes {\n")
end_index = content.index("}\n", start_index) + 1

# Replace lines with filtered endpoints
new_lines = (
    ["upstream fullnodes {\n"]
    + [
        f"    server {endpoint.split('//')[1].split('/')[0]};\n"
        for endpoint in filtered_endpoints
    ]
    + ["}\n"]
)
content[start_index:end_index] = new_lines

# Write back to the file
with open(nginx_config, "w") as f:
    f.writelines(content)

print("\nNginx configuration updated!")
