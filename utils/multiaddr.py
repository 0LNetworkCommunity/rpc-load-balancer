def decode_multiaddr_simple(hex_string):
    """
    Simplified version without debug output.

    Args:
        hex_string (str): Hex string representation of multiaddr

    Returns:
        str: Decoded multiaddr string
    """
    # Remove 0x prefix if present
    hex_string = hex_string.replace("0x", "")

    # Convert hex to bytes
    bytes_data = bytes.fromhex(hex_string)

    components = []

    # Extract IP address (bytes 4-7)
    ip = f"{bytes_data[4]}.{bytes_data[5]}.{bytes_data[6]}.{bytes_data[7]}"
    components.append(f"/ip4/{ip}")

    # Extract port (bytes 9-10, little-endian)
    port = (bytes_data[10] << 8) | bytes_data[9]
    components.append(f"/tcp/{port}")

    # Extract key length and key (byte 12 is length, then key data)
    key_length = bytes_data[12]
    key_bytes = bytes_data[13 : 13 + key_length]
    key_hex = key_bytes.hex()
    components.append(f"/noise-ik/0x{key_hex}")

    # Add handshake
    components.append("/handshake/0")

    return "".join(components)
