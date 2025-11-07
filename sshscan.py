#!/usr/bin/env python3
# The MIT License (MIT)
#
# Copyright (c) 2017 Vincent Ruijter
# Copyright (c) 2020 Babak Farrokhi
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Cipher detection based on: https://stribika.github.io/2015/01/04/secure-secure-shell.html
#

import socket
import struct
import sys


# SSH Protocol Constants
SSH_MSG_KEXINIT = 20


def parse_uint32(data: bytes, offset: int) -> tuple:
    """Parse a 4-byte big-endian unsigned integer. Returns (value, new_offset)."""
    if offset + 4 > len(data):
        raise ValueError("Insufficient data to parse uint32")
    value = struct.unpack('>I', data[offset:offset + 4])[0]
    return value, offset + 4


def parse_byte(data: bytes, offset: int) -> tuple:
    """Parse a single byte. Returns (value, new_offset)."""
    if offset >= len(data):
        raise ValueError("Insufficient data to parse byte")
    return data[offset], offset + 1


def parse_string(data: bytes, offset: int) -> tuple:
    """Parse a length-prefixed string. Returns (string_bytes, new_offset)."""
    length, offset = parse_uint32(data, offset)
    if offset + length > len(data):
        raise ValueError("Insufficient data to parse string of length %d" % length)
    string_data = data[offset:offset + length]
    return string_data, offset + length


def parse_name_list(data: bytes, offset: int) -> tuple:
    """Parse a name-list (comma-separated algorithm names). Returns (list, new_offset)."""
    name_list_bytes, offset = parse_string(data, offset)
    if len(name_list_bytes) == 0:
        return [], offset
    name_list_str = name_list_bytes.decode('ascii')
    names = name_list_str.split(',')
    return names, offset


def parse_boolean(data: bytes, offset: int) -> tuple:
    """Parse a boolean byte. Returns (bool_value, new_offset)."""
    value, offset = parse_byte(data, offset)
    return value != 0, offset


def parse_ssh_packet(conn: socket.socket) -> bytes:
    """
    Read and parse an SSH binary packet from the connection.
    Returns the payload bytes (without padding).
    """
    header = conn.recv(5)
    if len(header) < 5:
        raise ValueError("Failed to read SSH packet header")

    packet_length = struct.unpack('>I', header[0:4])[0]
    padding_length = header[4]

    if packet_length < 1 or packet_length > 1024 * 1024:
        raise ValueError("Invalid packet length: %d" % packet_length)

    remaining = packet_length - 1
    data = b''
    while len(data) < remaining:
        chunk = conn.recv(remaining - len(data))
        if not chunk:
            raise ValueError("Connection closed while reading packet")
        data += chunk

    payload_length = packet_length - padding_length - 1
    payload = data[0:payload_length]

    return payload


def parse_kexinit(payload: bytes) -> dict:
    """
    Parse SSH_MSG_KEXINIT message payload.
    Returns a dictionary with all the algorithm lists.
    """
    offset = 0

    msg_type, offset = parse_byte(payload, offset)
    if msg_type != SSH_MSG_KEXINIT:
        raise ValueError("Expected SSH_MSG_KEXINIT (20), got %d" % msg_type)

    offset += 16

    kex_algorithms, offset = parse_name_list(payload, offset)
    server_host_key_algorithms, offset = parse_name_list(payload, offset)
    encryption_algorithms_c2s, offset = parse_name_list(payload, offset)
    encryption_algorithms_s2c, offset = parse_name_list(payload, offset)
    mac_algorithms_c2s, offset = parse_name_list(payload, offset)
    mac_algorithms_s2c, offset = parse_name_list(payload, offset)
    compression_algorithms_c2s, offset = parse_name_list(payload, offset)
    compression_algorithms_s2c, offset = parse_name_list(payload, offset)
    languages_c2s, offset = parse_name_list(payload, offset)
    languages_s2c, offset = parse_name_list(payload, offset)

    first_kex_packet_follows, offset = parse_boolean(payload, offset)
    reserved, offset = parse_uint32(payload, offset)

    return {
        'kex_algorithms': kex_algorithms,
        'server_host_key_algorithms': server_host_key_algorithms,
        'encryption_algorithms_client_to_server': encryption_algorithms_c2s,
        'encryption_algorithms_server_to_client': encryption_algorithms_s2c,
        'mac_algorithms_client_to_server': mac_algorithms_c2s,
        'mac_algorithms_server_to_client': mac_algorithms_s2c,
        'compression_algorithms_client_to_server': compression_algorithms_c2s,
        'compression_algorithms_server_to_client': compression_algorithms_s2c,
        'languages_client_to_server': languages_c2s,
        'languages_server_to_client': languages_s2c,
        'first_kex_packet_follows': first_kex_packet_follows,
        'reserved': reserved
    }


def exchange(ip: str, port: int) -> dict:
    """
    Connect to SSH server and retrieve KEXINIT data.
    Returns a dictionary with algorithm lists, or None on failure.
    """
    kexinit_data = None
    try:
        conn = socket.create_connection((ip, port), timeout=5)
        print("[*] Connected to %s on port %i..." % (ip, port))

        version_data = conn.recv(255)
        if not version_data or b'\n' not in version_data:
            raise ValueError("Failed to receive SSH version string")

        version = version_data.decode('ascii', errors='ignore').split('\n')[0].strip()
        print("    [+] Target SSH version is: %s" % version)

        conn.send(b'SSH-2.0-OpenSSH_6.0p1\r\n')
        print("    [+] Retrieving algorithm information...")

        payload = parse_ssh_packet(conn)
        kexinit_data = parse_kexinit(payload)

        conn.close()

    except Exception as e:
        print("[-] Error while connecting to %s on port %i: %s" % (ip, port, e))

    return kexinit_data


def validate_port(port_str):
    """Validate that port is a valid integer in range 1-65535."""
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            return None, "Port must be between 1 and 65535"
        return port, None
    except ValueError:
        return None, "Port must be a valid integer"


def parse_target(target):
    """Parse target string to extract host and port, handling IPv6 addresses."""
    port = 22
    host = target

    # Handle [host]:port format (used for IPv6)
    if target.startswith('['):
        bracket_end = target.find(']')
        if bracket_end == -1:
            return None, None, "Invalid format: missing closing bracket"

        host = target[1:bracket_end]

        # Check if port is specified after the bracket
        if bracket_end + 1 < len(target):
            if target[bracket_end + 1] != ':':
                return None, None, "Invalid format: expected ':' after bracket"
            port_str = target[bracket_end + 2:]
            if not port_str:
                return None, None, "Invalid format: missing port after ':'"
            port, error = validate_port(port_str)
            if error:
                return None, None, error
    # Handle host:port format (IPv4 or hostname)
    elif ':' in target:
        # Check if this might be an IPv6 address without brackets
        colon_count = target.count(':')
        if colon_count > 1:
            return None, None, "Invalid format: IPv6 addresses must be enclosed in brackets [host]:port"

        parts = target.split(':')
        host = parts[0]
        port, error = validate_port(parts[1])
        if error:
            return None, None, error

    return host, port, None


def scan_target(target):
    """
    Scan target SSH server and display results.
    Returns 0 on success, 1 on failure.
    """
    host, port, error = parse_target(target)

    if error:
        print("[-] Error: %s" % error)
        return 1

    if not host or not host.strip():
        print("[-] Error: Hostname cannot be empty")
        return 1

    print("[*] Initiating scan for %s on port %d" % (host, port))
    kexinit_data = exchange(host, port)
    if kexinit_data:
        display_result(kexinit_data)
        return 0
    else:
        return 1


def print_algo_list(algo_list: list, title: str):
    if algo_list:
        print('    [+] Detected %s: ' % title)
        # adjust the amount of columns to display
        cols = 2
        while len(algo_list) % cols != 0:
            algo_list.append('')
        else:
            split = [algo_list[i:i + len(algo_list) // cols] for i in
                     range(0, len(algo_list), len(algo_list) // cols)]
            for row in zip(*split):
                print("          " + "".join(str.ljust(c, 37) for c in row))
    else:
        print('    [-] No %s detected!' % title)


def detect_weak_algo(detected_list: list, strong_list: list) -> list:
    """Identify weak algorithms by comparing detected against strong list."""
    weak = []
    for algo in detected_list:
        if algo not in strong_list:
            weak.append(algo)
    return weak


def display_result(kexinit_data: dict):
    """Display KEXINIT algorithm information and identify weak algorithms."""

    strong_ciphers = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                      'aes256-ctr', 'aes192-ctr', 'aes128-ctr']

    strong_macs = ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'umac-128',
                   'umac-128-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256', 'umac-128@openssh.com']

    strong_kex = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256',
                  'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
                  'sntrup761x25519-sha512@openssh.com', 'sntrup761x25519-sha512', 'mlkem768x25519-sha256',
                  'kex-strict-s-v00@openssh.com', 'ext-info-s']

    strong_hka = ['ssh-rsa-cert-v01@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'ssh-rsa-cert-v00@openssh.com',
                  'ssh-rsa', 'ssh-ed25519', 'rsa-sha2-256', 'rsa-sha2-512']

    detected_ciphers = kexinit_data['encryption_algorithms_server_to_client']
    detected_kex = kexinit_data['kex_algorithms']
    detected_macs = kexinit_data['mac_algorithms_server_to_client']
    detected_hka = kexinit_data['server_host_key_algorithms']

    weak_ciphers = detect_weak_algo(detected_ciphers, strong_ciphers)
    weak_kex = detect_weak_algo(detected_kex, strong_kex)
    weak_macs = detect_weak_algo(detected_macs, strong_macs)
    weak_hka = detect_weak_algo(detected_hka, strong_hka)

    print_algo_list(detected_ciphers, 'ciphers')
    print_algo_list(detected_kex, 'KEX algorithms')
    print_algo_list(detected_macs, 'MACs')
    print_algo_list(detected_hka, 'HostKey algorithms')

    print_algo_list(weak_ciphers, 'weak ciphers')
    print_algo_list(weak_kex, 'weak KEX algorithms')
    print_algo_list(weak_macs, 'weak MACs')
    print_algo_list(weak_hka, 'weak HostKey algorithms')

    compression_algos = kexinit_data['compression_algorithms_server_to_client']
    if 'zlib@openssh.com' in compression_algos or 'zlib' in compression_algos:
        print('    [+] Compression is enabled')
    else:
        print('    [-] Compression is *not* enabled')


def main():
    if len(sys.argv) < 2:
        print("[-] No target specified!")
        print("Syntax: %s host.example.com[:22]" % sys.argv[0])
        sys.exit(1)

    exit_code = scan_target(sys.argv[1])
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
