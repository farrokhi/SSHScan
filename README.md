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
% ./sshscan.py  sdf.org

[*] Initiating scan for sdf.org on port 22
[*] Connected to sdf.org on port 22...
    [+] Target SSH version is: SSH-2.0-OpenSSH_8.0
    [+] Retrieving ciphers...
    [+] Detected ciphers:
          aes128-ctr                           aes256-ctr
          aes128-gcm@openssh.com               aes256-gcm@openssh.com
          aes192-ctr                           chacha20-poly1305@openssh.com
    [+] Detected KEX algorithms:
          curve25519-sha256                    diffie-hellman-group16-sha512
          curve25519-sha256@libssh.org         diffie-hellman-group18-sha512
          diffie-hellman-group-exchange-sha256 ecdh-sha2-nistp256
          diffie-hellman-group14-sha1          ecdh-sha2-nistp384
          diffie-hellman-group14-sha256        ecdh-sha2-nistp521
    [+] Detected MACs:
          hmac-sha1                            hmac-sha2-512-etm@openssh.com
          hmac-sha1-etm@openssh.com            umac-128-etm@openssh.com
          hmac-sha2-256                        umac-128@openssh.com
          hmac-sha2-256-etm@openssh.com        umac-64-etm@openssh.com
          hmac-sha2-512                        umac-64@openssh.com
    [+] Detected HostKey algorithms:
          rsa-sha2-256                         ssh-ed25519
          rsa-sha2-512                         ssh-rsa
    [-] No weak ciphers detected!
    [+] Detected weak KEX algorithms:
          diffie-hellman-group14-sha1          ecdh-sha2-nistp384
          ecdh-sha2-nistp256                   ecdh-sha2-nistp521
    [+] Detected weak MACs:
          hmac-sha1                            umac-64-etm@openssh.com
          hmac-sha1-etm@openssh.com            umac-64@openssh.com
    [-] No weak HostKey algorithms detected!
    [-] Compression is *not* enabled
```

-----
This is originally based on https://github.com/evict/SSHScan

