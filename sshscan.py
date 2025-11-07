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

import re
import socket
import sys


def exchange(ip: str, port: int) -> str:
    ciphers = ''
    try:
        conn = socket.create_connection((ip, port), timeout=5)
        print("[*] Connected to %s on port %i..." % (ip, port))
        version = conn.recv(50).decode().split('\n')[0]
        conn.send(b'SSH-2.0-OpenSSH_6.0p1\r\n')
        print("    [+] Target SSH version is: %s" % version)
        print("    [+] Retrieving ciphers...")
        ciphers = conn.recv(984).decode(errors='ignore')
        conn.close()

    except Exception as e:
        print("[-] Error while connecting to %s on port %i: %s" % (ip, port, e))

    return ciphers


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
    detected_ciphers = exchange(host, port)
    if detected_ciphers:
        display_result(detected_ciphers)
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


def display_result(given_algo: str):
    all_ciphers = ['3des', '3des-cbc', 'acss@openssh.org', 'aes128-cbc', 'aes128-ctr', 'aes128-gcm@openssh.com',
                   'aes192-cbc', 'aes192-ctr', 'aes256-cbc', 'aes256-ctr', 'aes256-gcm@openssh.com', 'arcfour',
                   'arcfour128', 'arcfour256', 'blowfish', 'blowfish-cbc', 'cast128-cbc',
                   'chacha20-poly1305@openssh.com', 'rijndael-cbc@lysator.liu.se']
    strong_ciphers = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                      'aes256-ctr', 'aes192-ctr', 'aes128-ctr']

    all_macs = ['hmac-md5', 'hmac-md5-96', 'hmac-md5-96-etm@openssh.com', 'hmac-md5-etm@openssh.com', 'hmac-ripemd160',
                'hmac-ripemd160-etm@openssh.com', 'hmac-ripemd160@openssh.com', 'hmac-sha1', 'hmac-sha1-96',
                'hmac-sha1-96-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha2-256',
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-512-etm@openssh.com',
                'hmac-sha256-96@ssh.com', 'hmac-sha256@ssh.com', 'umac-128-etm@openssh.com', 'umac-128@openssh.com',
                'umac-64-etm@openssh.com', 'umac-64@openssh.com']
    strong_macs = ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'umac-128',
                   'umac-128-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256', 'umac-128@openssh.com']

    all_kex = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha1',
               'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
               'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
               'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
               'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
               'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'sntrup4591761x25519-sha512@tinyssh.org']
    strong_kex = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256',
                  'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512']

    all_hka = ['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384',
               'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp521',
               'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'rsa-sha2-256', 'rsa-sha2-256-cert-v01@openssh.com',
               'rsa-sha2-512', 'rsa-sha2-512-cert-v01@openssh.com', 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
               'sk-ecdsa-sha2-nistp256@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com',
               'sk-ssh-ed25519@openssh.com', 'ssh-dss', 'ssh-dss-cert-v00@openssh.com', 'ssh-dss-cert-v01@openssh.com',
               'ssh-dss-sha224@ssh.com', 'ssh-dss-sha256@ssh.com', 'ssh-dss-sha384@ssh.com', 'ssh-dss-sha512@ssh.com',
               'ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com', 'ssh-rsa', 'ssh-rsa-cert-v00@openssh.com',
               'ssh-rsa-cert-v01@openssh.com', 'ssh-rsa-sha224@ssh.com', 'ssh-rsa-sha256@ssh.com',
               'ssh-rsa-sha384@ssh.com', 'ssh-rsa-sha512@ssh.com', 'ssh-xmss-cert-v01@openssh.com',
               'ssh-xmss@openssh.com', 'x509v3-sign-dss', 'x509v3-sign-dss-sha224@ssh.com',
               'x509v3-sign-dss-sha256@ssh.com', 'x509v3-sign-dss-sha384@ssh.com', 'x509v3-sign-dss-sha512@ssh.com',
               'x509v3-sign-rsa', 'x509v3-sign-rsa-sha224@ssh.com', 'x509v3-sign-rsa-sha256@ssh.com',
               'x509v3-sign-rsa-sha384@ssh.com', 'x509v3-sign-rsa-sha512@ssh.com']
    strong_hka = ['ssh-rsa-cert-v01@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'ssh-rsa-cert-v00@openssh.com',
                  'ssh-rsa', 'ssh-ed25519', 'rsa-sha2-256', 'rsa-sha2-512']

    detected_macs, weak_macs = detect_algo(given_algo, all_macs, strong_macs)
    detected_ciphers, weak_ciphers = detect_algo(given_algo, all_ciphers, strong_ciphers)
    detected_kex, weak_kex = detect_algo(given_algo, all_kex, strong_kex)
    detected_hka, weak_hka = detect_algo(given_algo, all_hka, strong_hka)

    print_algo_list(detected_ciphers, 'ciphers')
    print_algo_list(detected_kex, 'KEX algorithms')
    print_algo_list(detected_macs, 'MACs')
    print_algo_list(detected_hka, 'HostKey algorithms')

    print_algo_list(weak_ciphers, 'weak ciphers')
    print_algo_list(weak_kex, 'weak KEX algorithms')
    print_algo_list(weak_macs, 'weak MACs')
    print_algo_list(weak_hka, 'weak HostKey algorithms')

    if re.search('zlib@openssh.com', given_algo):
        print('    [+] Compression is enabled')
    else:
        print('    [-] Compression is *not* enabled')


def detect_algo(given_algo, all_algo, strong_algo):
    _detected = []
    _weak = []
    for i in all_algo:
        m = re.search(i, given_algo)
        if m:
            _detected.append(i)
            if i not in strong_algo:
                _weak.append(i)
    return _detected, _weak


def main():
    if len(sys.argv) < 2:
        print("[-] No target specified!")
        print("Syntax: %s host.example.com[:22]" % sys.argv[0])
        sys.exit(1)

    exit_code = scan_target(sys.argv[1])
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
