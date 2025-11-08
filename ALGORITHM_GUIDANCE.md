# SSH Algorithm Security Reference

This document summarizes which SSH algorithms are considered secure or insecure for use in sshscan.py. Each classification is supported by peer-reviewed research papers, IETF RFCs, and OpenSSH protocol documentation from the cryptographers who designed these algorithms. NIST sources were intentionally excluded from this analysis.

## Ciphers

### Secure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `chacha20-poly1305@openssh.com` | AEAD construction from ChaCha20 stream cipher and Poly1305 authenticator with proofs of security and an OpenSSH instantiation. | [Bernstein 2008](https://cr.yp.to/chacha/chacha-20080128.pdf), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), [OpenSSH PROTOCOL.chacha20poly1305](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.chacha20poly1305) |
| `aes256-gcm@openssh.com` | AES-GCM provides provable IND-CCA security with minimal overhead and is recommended by the mode's designers. | [McGrew & Viega 2004](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm02/McGrewViega.pdf) |
| `aes128-gcm@openssh.com` | Same AEAD construction and proofs apply to 128-bit keys. | [McGrew & Viega 2004](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm02/McGrewViega.pdf) |
| `aes256-ctr` | Counter mode keeps AES in a provably secure stream configuration when paired with a strong MAC, and RFC 4344 standardizes it for SSH. | [RFC 4344](https://www.rfc-editor.org/rfc/rfc4344) |
| `aes192-ctr` | Same security argument as the 256-bit variant. | [RFC 4344](https://www.rfc-editor.org/rfc/rfc4344) |
| `aes128-ctr` | Same security argument as the 256-bit variant. | [RFC 4344](https://www.rfc-editor.org/rfc/rfc4344) |

### Insecure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `3des-cbc` | 64-bit block cipher vulnerable to the Sweet32 birthday attack against long-lived SSH sessions. | [Bhargavan & Leurent 2016](https://sweet32.info/SWEET32_CCS16.pdf) |
| `blowfish-cbc` | 64-bit block cipher subject to the same Sweet32 collision limits. | [Bhargavan & Leurent 2016](https://sweet32.info/SWEET32_CCS16.pdf) |
| `cast128-cbc` | 64-bit block cipher subject to the same Sweet32 collision limits. | [Bhargavan & Leurent 2016](https://sweet32.info/SWEET32_CCS16.pdf) |
| `arcfour`, `arcfour128`, `arcfour256` | RC4 stream cipher exhibits serious bias attacks that recover keystream bytes in practice. | [AlFardan et al. 2013](https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper-alfardan.pdf) |
| `aes256-cbc`, `aes192-cbc`, `aes128-cbc` | CBC mode without Encrypt-then-MAC suffers from practical padding-oracle attacks such as Lucky13. | [AlFardan & Paterson 2013](https://www.ieee-security.org/TC/SP2013/papers/4977a526.pdf) |

## Message Authentication Codes

### Secure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `hmac-sha2-512-etm@openssh.com` | HMAC inherits SHA-512's collision resistance and Encrypt-then-MAC prevents padding oracles. | [Bellare, Canetti & Krawczyk 1996](https://cseweb.ucsd.edu/~mihir/papers/hmac.pdf), [Krawczyk 2001](https://iacr.org/archive/crypto2001/21390229.pdf) |
| `hmac-sha2-256-etm@openssh.com` | Same guarantees as the 512-bit variant. | [Bellare, Canetti & Krawczyk 1996](https://cseweb.ucsd.edu/~mihir/papers/hmac.pdf), [Krawczyk 2001](https://iacr.org/archive/crypto2001/21390229.pdf) |
| `hmac-sha2-512` | HMAC proof gives strong unforgeability so long as SHA-512 remains preimage-resistant. | [Bellare, Canetti & Krawczyk 1996](https://cseweb.ucsd.edu/~mihir/papers/hmac.pdf) |
| `hmac-sha2-256` | Same proof applies to the 256-bit digest. | [Bellare, Canetti & Krawczyk 1996](https://cseweb.ucsd.edu/~mihir/papers/hmac.pdf) |
| `umac-128-etm@openssh.com` | UMAC's ε-almost-universal hash guarantees 128-bit tag security and EtM hardens SSH framing. | [Black et al. 1999](https://link.springer.com/chapter/10.1007/3-540-48405-1_24), [Krawczyk 2001](https://iacr.org/archive/crypto2001/21390229.pdf) |
| `umac-128@openssh.com` | Same ε-almost-universal hash analysis applies when SSH performs integrity then encryption. | [Black et al. 1999](https://link.springer.com/chapter/10.1007/3-540-48405-1_24) |
| `umac-128` | Same as above for the generic algorithm name. | [Black et al. 1999](https://link.springer.com/chapter/10.1007/3-540-48405-1_24) |

### Insecure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `hmac-sha1`, `hmac-sha1-96` | While HMAC-SHA1 remains theoretically secure against collision attacks, it is deprecated due to reduced cryptographic margins and industry best practices recommend migration to SHA-2 based MACs. | [Stevens et al. 2017](https://shattered.io/static/shattered.pdf), [Bellare et al. 2006](https://eprint.iacr.org/2006/043.pdf) |
| `hmac-md5`, `hmac-md5-96` | MD5 collision attacks invalidate HMAC-MD5's binding. | [Wang & Yu 2005](https://link.springer.com/chapter/10.1007/11426639_1) |
| `umac-64` | 64-bit tags only give 32-bit birthday security, which UMAC's own analysis warns is insufficient for modern SSH volumes. | [Black et al. 1999](https://link.springer.com/chapter/10.1007/3-540-48405-1_24) |
| `none` | Disables integrity entirely and violates SSH's mandatory MAC requirement. | [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253) |

## Key Exchange Algorithms

### Secure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `curve25519-sha256` | Twist-secure Montgomery curve with security slightly under 128 bits and well-analyzed implementations. | [Bernstein 2006](https://cr.yp.to/ecdh/curve25519-20060209.pdf), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| `curve25519-sha256@libssh.org` | Same properties as above, differing only in identification string. | [Bernstein 2006](https://cr.yp.to/ecdh/curve25519-20060209.pdf), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| `diffie-hellman-group14-sha256` | 2048-bit MODP group delivers ~112-bit strength and avoids SHA-1 collisions. | [Lenstra & Verheul 2001](https://link.springer.com/article/10.1007/s00145-001-0009-4), [Adrian et al. 2015](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf) |
| `diffie-hellman-group16-sha512` | 4096-bit MODP group maps to ~152-bit strength. | [Lenstra & Verheul 2001](https://link.springer.com/article/10.1007/s00145-001-0009-4) |
| `diffie-hellman-group18-sha512` | 8192-bit MODP group exceeds 192-bit strength targets. | [Lenstra & Verheul 2001](https://link.springer.com/article/10.1007/s00145-001-0009-4) |
| `diffie-hellman-group-exchange-sha256` | Ephemeral MODP parameters sized per policy mitigate precomputation per Logjam guidance. | [Adrian et al. 2015](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf) |
| `sntrup761x25519-sha512@openssh.com` | Combines NTRU Prime (post-quantum) with Curve25519 (classical) for hybrid security. | [Bernstein et al. 2017](https://ntruprime.cr.yp.to/ntruprime-20170628.pdf), [OpenSSH sshd_config](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5) |
| `sntrup761x25519-sha512` | Same construction as above without the OpenSSH suffix. | [Bernstein et al. 2017](https://ntruprime.cr.yp.to/ntruprime-20170628.pdf), [OpenSSH sshd_config](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5) |
| `mlkem768x25519-sha256` | Hybrid Kyber (ML-KEM-768) plus Curve25519 exchange vetted by the Kyber team. | [Bos et al. 2017](https://eprint.iacr.org/2017/634.pdf), [OpenSSH sshd_config](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5) |
| `kex-strict-s-v00@openssh.com` | OpenSSH strict key exchange extension mitigates CVE-2023-48795 (Terrapin attack) by enforcing strict message sequencing and resetting sequence numbers after key exchange. | [OpenSSH sshd_config](https://github.com/openssh/openssh-portable/blob/master/sshd_config.5), [Terrapin Attack](https://terrapin-attack.com) |
| `ext-info-s` | RFC 8308 extension provides capability discovery after key exchange, enabling negotiation of additional features. Used with kex-strict for enhanced security. | [RFC 8308](https://www.rfc-editor.org/rfc/rfc8308) |

### Insecure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `diffie-hellman-group1-sha1` | 1024-bit MODP group falls to the Logjam precomputation attack. | [Adrian et al. 2015](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf) |
| `diffie-hellman-group14-sha1` | Although the modulus is large enough, the SHA-1 hash in the transcript is collision-prone. | [Stevens et al. 2017](https://shattered.io/static/shattered.pdf) |
| `diffie-hellman-group-exchange-sha1` | Same SHA-1 transcript risk as above plus potential parameter downgrades. | [Stevens et al. 2017](https://shattered.io/static/shattered.pdf) |

## Host-Key Algorithms

### Secure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `ssh-ed25519` | Ed25519 provides deterministic, side-channel resistant signatures at the 128-bit security level. | [Bernstein et al. 2012](https://cr.yp.to/papers/ed25519-20110926.pdf), [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709) |
| `ssh-ed25519-cert-v01@openssh.com` | Same Ed25519 guarantees with OpenSSH certificate framing. | [Bernstein et al. 2012](https://cr.yp.to/papers/ed25519-20110926.pdf), [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709) |
| `rsa-sha2-256` | RSA signatures hardened with SHA-256 resist the SHA-1 collision class of attacks. | [Boneh & Shoup 2020](https://toc.cryptobook.us/book.pdf), [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332) |
| `rsa-sha2-512` | Same as above with a larger digest. | [Boneh & Shoup 2020](https://toc.cryptobook.us/book.pdf), [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332) |
| `ssh-rsa-cert-v01@openssh.com` (Use with rsa-sha2-256/512) | Certificates inherit the stronger SHA-2 RSA signatures when configured accordingly. | [Boneh & Shoup 2020](https://toc.cryptobook.us/book.pdf), [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332) |

### Insecure

| Algorithm | Rationale | References |
| --- | --- | --- |
| `ssh-rsa` | Uses SHA-1 signatures, which are forgeable via chosen-prefix collisions. | [Stevens et al. 2017](https://shattered.io/static/shattered.pdf) |
| `ssh-rsa-cert-v00@openssh.com` | Certificate flavor that still relies on SHA-1 signatures. | [Stevens et al. 2017](https://shattered.io/static/shattered.pdf) |
| `ssh-dss` | DSA keys are permanently limited to 1024 bits and were disabled by OpenSSH for insufficient security margin. | [OpenSSH 7.0 Release Notes](https://www.openssh.org/txt/release-7.0) |
