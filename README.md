SSHScan
=======

[![CI](https://github.com/farrokhi/SSHScan/actions/workflows/ci.yml/badge.svg)](https://github.com/farrokhi/SSHScan/actions/workflows/ci.yml)

SSHScan is a remote auditing tool that enumerates SSH server cryptographic algorithms. It helps identify weak or deprecated ciphers, key exchange algorithms, MACs, and host key algorithms.

Requirements
============

SSHScan requires Python 3.8 or newer and has no dependency on third-party packages. It uses only the Python standard library.

Installation
============

```bash
git clone https://github.com/farrokhi/SSHScan
cd SSHScan
```

Usage
=====

Basic usage:
```bash
./sshscan.py host.example.com
```

Specify a custom port:
```bash
./sshscan.py host.example.com:2222
```

IPv6 addresses must be enclosed in brackets and quoted:
```bash
./sshscan.py '[2001:db8::1]:22'
./sshscan.py '[::1]'
```

Display help:
```bash
./sshscan.py -h
```

Sample output:
```
% ./sshscan.py sdf.org

[*] Initiating scan for sdf.org on port 22
[*] Connected to sdf.org on port 22...
    [+] Target SSH version is: SSH-2.0-OpenSSH_10.0
    [+] Retrieving algorithm information...
    [+] Detected ciphers:
          chacha20-poly1305@openssh.com        aes128-ctr
          aes128-gcm@openssh.com               aes192-ctr
          aes256-gcm@openssh.com               aes256-ctr
    [+] Detected KEX algorithms:
          mlkem768x25519-sha256                ecdh-sha2-nistp256
          sntrup761x25519-sha512               ecdh-sha2-nistp384
          sntrup761x25519-sha512@openssh.com   ecdh-sha2-nistp521
          curve25519-sha256                    ext-info-s
          curve25519-sha256@libssh.org         kex-strict-s-v00@openssh.com
    [+] Detected MACs:
          umac-64-etm@openssh.com              umac-64@openssh.com
          umac-128-etm@openssh.com             umac-128@openssh.com
          hmac-sha2-256-etm@openssh.com        hmac-sha2-256
          hmac-sha2-512-etm@openssh.com        hmac-sha2-512
          hmac-sha1-etm@openssh.com            hmac-sha1
    [+] Detected HostKey algorithms:
          rsa-sha2-512                         ssh-ed25519
          rsa-sha2-256
    [-] No weak ciphers detected!
    [+] Detected weak KEX algorithms:
          ecdh-sha2-nistp256                   ecdh-sha2-nistp521
          ecdh-sha2-nistp384
    [+] Detected weak MACs:
          umac-64-etm@openssh.com              umac-64@openssh.com
          hmac-sha1-etm@openssh.com            hmac-sha1
    [-] No weak HostKey algorithms detected!
    [+] Compression is enabled
```

-----
This is originally based on https://github.com/evict/SSHScan

