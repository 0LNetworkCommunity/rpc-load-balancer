import sys
import requests
from utils.multiaddr import decode_multiaddr_simple

# Tolerance of max height: fixed count integer
balancer_tolerance = 500  # This is the fixed count integer tolerance


# nginx_config = "/etc/nginx/sites-available/rpc-load-balancer"
nginx_config = sys.argv[1]

# Read endpoints from the adjacent file
with open("endpoints.txt", "r") as f:
    endpoints = [line.strip() for line in f.readlines() if not line.startswith("#")]

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
                if network_addresses:
                    # Decode the multiaddr to get IP addresses
                    decoded = decode_multiaddr_simple(network_addresses)
                    # Extract IPv4 addresses from the decoded multiaddr string
                    # The decoded format might be like "/ip4/1.2.3.4/tcp/6180/..."
                    parts = decoded.split("/")
                    for i, part in enumerate(parts):
                        if part == "ip4" and i + 1 < len(parts):
                            ips.append(parts[i + 1])

                # Also check fullnode addresses
                fullnode_addresses = resource["data"].get("fullnode_addresses", "")
                if fullnode_addresses:
                    decoded = decode_multiaddr_simple(fullnode_addresses)
                    parts = decoded.split("/")
                    for i, part in enumerate(parts):
                        if part == "ip4" and i + 1 < len(parts):
                            ips.append(parts[i + 1])
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


# Get validator universe and active validator set
print("Fetching validator universe and active validator set...")
validator_universe, active_validators = get_validator_info()
print(
    f"Found {len(validator_universe)} validators in universe, {len(active_validators)} active"
)

# Build a map of IPs to validator addresses
ip_to_validator = {}
validator_to_active = {v: v in active_validators for v in validator_universe}

print("Fetching validator network addresses...")
for validator in validator_universe:
    ips = get_validator_ips(validator)
    for ip in ips:
        ip_to_validator[ip] = validator
    if ips:
        print(f"Validator {validator}: IPs {ips}")

# Fetch ledger_version from each endpoint
ledger_versions = {}
for endpoint in endpoints:
    if len(endpoint) > 0:
        try:
            response = requests.get(endpoint, timeout=5)
            data = response.json()
            ledger_version = int(data.get("ledger_version"))
            if (
                isinstance(ledger_version, int) and ledger_version > 0
            ):  # Ensure ledger_version is an integer
                ledger_versions[endpoint] = int(ledger_version)
        except Exception as e:
            print(f"Error fetching data from {endpoint}: {e}")

print(ledger_versions)

# Find the highest ledger_version
if not ledger_versions:
    print("No valid endpoints found!")
    sys.exit(1)

max_version = max(ledger_versions.values())

# Filter out endpoints that are within a range ±tolerance of the highest ledger_version
top_endpoints = [
    endpoint
    for endpoint, version in ledger_versions.items()
    if (max_version - balancer_tolerance)
    <= version
    <= (max_version + balancer_tolerance)
]

# Filter out VFN endpoints from validators not in active set
filtered_endpoints = []
for endpoint in top_endpoints:
    ip = extract_ip_from_endpoint(endpoint)
    if ip and ip in ip_to_validator:
        validator = ip_to_validator[ip]
        if validator_to_active.get(validator, False):
            # Validator is active, keep the endpoint
            filtered_endpoints.append(endpoint)
            print(f"Keeping endpoint {endpoint} (active validator {validator})")
        else:
            # Validator is not active, this is a VFN we should exclude
            print(f"Excluding VFN endpoint {endpoint} (inactive validator {validator})")
    else:
        # Not a VFN endpoint or couldn't determine, keep it
        filtered_endpoints.append(endpoint)

print(f"\nFiltered {len(top_endpoints) - len(filtered_endpoints)} VFN endpoints")
print(f"Final endpoint count: {len(filtered_endpoints)}")

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

print("Nginx configuration updated!")
