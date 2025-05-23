def decode_multiaddr(hex_string):
    """
    Decode a multiaddr hex string into human-readable format.

    Args:
        hex_string (str): Hex string representation of multiaddr

    Returns:
        str: Decoded multiaddr string
    """
    # Remove 0x prefix if present
    hex_string = hex_string.replace("0x", "")

    # Convert hex to bytes
    bytes_data = bytes.fromhex(hex_string)

    print(f"Total bytes: {len(bytes_data)}")
    print(f'Hex bytes: {" ".join(f"{b:02x}" for b in bytes_data)}')

    components = []
    pos = 0

    # Skip protocol family indicator (bytes 0-1)
    print(f"Bytes 0-1: Protocol family (0x{bytes_data[0]:02x} 0x{bytes_data[1]:02x})")
    pos = 2

    # IP4 protocol (byte 2) + padding (byte 3)
    print(f"Bytes 2-3: IP4 protocol (0x{bytes_data[2]:02x} 0x{bytes_data[3]:02x})")
    pos = 4

    # Read IP address (4 bytes)
    ip = (
        f"{bytes_data[pos]}.{bytes_data[pos+1]}.{bytes_data[pos+2]}.{bytes_data[pos+3]}"
    )
    print(f"Bytes 4-7: IP address = {ip}")
    components.append(f"/ip4/{ip}")
    pos += 4

    # Skip length indicator (byte 8)
    print(f"Byte 8: Length indicator (0x{bytes_data[pos]:02x})")
    pos += 1

    # Read port (2 bytes, little-endian)
    port = (bytes_data[pos + 1] << 8) | bytes_data[pos]
    print(
        f"Bytes 9-10: Port = {port} (little-endian: 0x{bytes_data[pos]:02x} 0x{bytes_data[pos+1]:02x})"
    )
    components.append(f"/tcp/{port}")
    pos += 2

    # Skip another length indicator (byte 11)
    print(f"Byte 11: Length indicator (0x{bytes_data[pos]:02x})")
    pos += 1

    # Read key length (byte 12)
    key_length = bytes_data[pos]
    print(f"Byte 12: Key length = {key_length}")
    pos += 1

    # Read the key data
    key_bytes = bytes_data[pos : pos + key_length]
    key_hex = key_bytes.hex()
    print(f"Bytes 13-{12 + key_length}: Key = {key_hex}")
    components.append(f"/noise-ik/0x{key_hex}")
    pos += key_length

    # Read handshake protocol (last 2 bytes)
    if pos < len(bytes_data) - 1:
        print(
            f"Bytes {pos}-{pos+1}: Handshake protocol (0x{bytes_data[pos]:02x} 0x{bytes_data[pos+1]:02x})"
        )
        components.append("/handshake/0")

    result = "".join(components)
    print(f"\nDecoded multiaddr: {result}")
    return result


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


# Example usage:
if __name__ == "__main__":
    hex_input = "012d0400ccba4a2c05241807203c37c7d6a5122a6b9ef07a11cc40e445874eb0841ae028d6326bf67768cce2350800"

    print("=== Detailed Decoding ===")
    decoded = decode_multiaddr(hex_input)

    print("\n=== Simple Decoding ===")
    decoded_simple = decode_multiaddr_simple(hex_input)
    print(f"Result: {decoded_simple}")

    # Expected output:
    expected = "/ip4/204.186.74.44/tcp/6180/noise-ik/0x3c37c7d6a5122a6b9ef07a11cc40e445874eb0841ae028d6326bf67768cce235/handshake/0"
    print(f"\nExpected: {expected}")
    print(f"Match: {decoded == expected}")
