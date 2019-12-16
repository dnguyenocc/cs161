# cs161
### Intro:
* Threat models and attacker motivations
* User behavior
* Vulnerability detection, false positives and negatives
* Defenses: password managers, security keys
### Security Principles:
* Defense in depth, security is economics, consider human factors, psychological acceptability
* Principle of least privilege, privilege separation, TCB, separation of responsibility, division of trust
* Complete mediation and reference monitors
* Strong as the weakest link, don't rely on security through obscurity, Shannon's Maxim/Kerckoff's Principle
* Fail-safe defaults, don't reinvent the wheel, go beyond the bare minimum
* Design in security from the start, proactively study attacks
### Memory Safety:
* TOCTTOU
* Buffer overflow, signed/unsigned numbers, fencepost/off-by-one errors
* Format string vulnerabilities, use after free
* Stack frames, canaries, entropy, NX bit, ASLR (by segments and for everything)
* Read, write, execute privileges, Data Execution Prevention (W^X)
* Preconditions, postconditions, invariants, memory safety vs. correctness
* ROP (including relevant reading for project: ret2ret, ret2pop, ret2esp, ret2eax, etc.)
* Testing and approaches for designing software

### Cryptography:
* Confidentiality, Integrity, Authentication, Non-repudiation
* Key generation, partial solutions/"leaking information"
* Ciphertext-only attack, IND-KPA, IND-CPA, chosen-ciphertext attack
* Basic ciphers: Caeser cipher, OTP, and their vulnerabilities + limitations
* Block ciphers: permutation (bijection), AES ECB, IV/Nonce, CBC, CTR, CFB (encryption, decryption, parallelization, IND-CPA or not?, IV reuse etc.), crib-dragging attack
* Cryptographic hashes, one-way/pre-image resistant, collision resistant, second pre-image resistant, SHA, file-sampling implementation MAC, HMAC, key reuse
* Password hashing, salt, slow hash, offline vs. online attacks, dictionary attack
* pRNG (entropy, seeds, etc.), rollback resistance, stream ciphers
### Public Key Cryptography:
* Symmetric vs. asymmetric
* Diffie-Hellman key exchange (procedure and vulnerabilities), eavesdropping vs. active MiTM, forward secrecy
* RSA encryption/decryption (including OAEP), timing attack, El Gamal encryption/decryption
* RSA signatures, DSA signatures, replay attack
* Certificates, validating certificates, certificate hierarchy, certificate authorities
* Certificate revocation: expiry, CRL, OCSP

*Applied Cryptography:*
* Fake and unusable cryptography examples
* Blockchain: hash chain, Merkle tree, cryptocurrency
* Bitcoin: mining/proof of work, consensus, irreversibility, censorship, etc.
### Web Security:
* Sanitizing user input, system, execv
* SQL: queries (SELECT, INSERT, DROP, etc.) and parsing
* SQL Attacks: injection, important characters for exploits (; -- " etc.), escaping user input, prepared statements/parameterized queries
* Marshal/unmarshal paradigms
* HTTP request and response, URL components (protocol, domain, etc.), domain hierarchy, CSS, Javascript (specific examples), parsers, DOM, and painter, frames, availability
* Web risks, sandboxing, same origin policy (SOP) (general, image tags, and iframes), server-side security, postMessage, web threats
* **Cookies**: purpose, read/set/delete/view, cookie policy/scope (read and set policies are different), flags, role of browser
* **CSRF** (subvert cookie policy), automatic web accesses, referrer URL (may not exist), secret tokens, samesite flag
* **XSS** (subvert SOP), stored XSS, reflected XSS, iframe usage, untrusted data insertion, HTML escaping, CSP
* **Clickjacking**: frame location, size, and transparency; keystrokes; user confirmation boxes, frame-busting, X-frames
* **Phishing**: user training, homograph attack, green and lock icons, browser-in-browser, transient phishing, reverse Turing test, outsourcing attack
### Network Basics:
* Protocol, packets (and their behavior)
* Layers: physical, link, network, transport, application; end-to-end vs hop-by-hop
* IP packet, MAC addresses and Ethernet header, hub, access point, packet injection, packet race conditions
### Network Protocols:
* WPA2, sniffing, subnet, brute-force attack, WPA enterprise (difference from WPA2), KRACK attack
* DHCP: messages and packet racing; switch, VLAN
* ARP
* UDP: header, best-effort, etc.
* DNS: resolver, requests (ID, question, answer, authority, additional, TTL), records and RRSETs, cache poisoning, bailiwick checking, dig, blind spoofing, Kaminsky glue attack (and defenses)
* IP: header (length, protocol, addresses, TTL), best effort, AS, BGP, reflected DOS attack
* TCP: connection-oriented, reliable, in-order, byte-stream, header (ports, sequence number, ACK number), flags (SYN, SYN-ACK, FIN, RST), data injection/connection hijacking, disruption, 3-way handshake
### Network Defenses:
* TLS: secure channel, green/lock icon, steps (nonces and protocol, certificate, PS, key generation, dialogue MACs), RSA vs Diffie-Hellman for PS (including forward secrecy), PKI, properties (confidentiality, integrity, authentication, but not availability)
* Trust and user involvement, certificate pinning and checking, rollback resistance (PRNG)
* DOS, DDOS, network filter, amplification attack, botnets, SYN flood, SYN cookies, application-layer DOS, DOS prevention
* Firewalls: access control policy, inbound vs. outbound, default allow vs. deny, stateful packet filter, firewall rule format, vulnerabilities (split data, reordering, TTL adjustment), application-level firewall, disadvantages
* DNSSEC: channel security vs. object/data security, flags (DO and CD), OPT resource record (CLASS field), RRSIG and its parts, DNSKEYs (KSK and ZSK), DS, benefits, NOERROR, NXDOMAIN, NSEC, enumeration attack and NSEC3, possible mistakes, DNSSEC transport

### Intrusion Detection Methods: 
* **NIDS** (pros/cons), inconsistency, ambiguity, evasion attacks, **HIDS** (pros/cons), **log analysis** (pros/cons), **syscall monitoring** (pros/cons, a type of HIDS)
* False positives and negatives, base rate fallacy, series and parallel composition, styles of detection (signature, specification, anomaly, behavior) (pros/cons of each), honeypots, attacks on IDSs
**Applied Topics:**
* NSA: user identification, XKEYSCORE, PGP, databases, QUANTUM etc., Great Cannon and Firewall, censorship
* Tor: threat model, onion routing, directory servers, crowd anonymity, exit nodes, pluggable transport, rendezvous, hidden services, dark markets, NITs
* Nuclear weapons: 2 main problems, PALs
* Viruses: propagation, detection, polymorphism, metamorphism, halting problem, cleanup, compiler backdoors, rootkits
* Worms: propagation, examples (Morris Worm, Code Red, Slammer, Witty, Stuxnet, NotPetya), scanning, growth rates/modeling, side effects, target lists, passiveness
* Botnets: bots, botmaster, C&C, prevention, countermeasures, bulletproof, DGAs, PPI, "milking", business models
* Hardware Attacks: privilege escalation attacks (Rowhammer), DRAM, kernel memory, flipping bits, virtual memory (page tables), side-channel attacks, caches, speculative execution (branch prediction, Meltdown), context switches
* Personal Security: threat models, backups, border crossing, SEP, OS security, AES-XEX, effaceable storage, transitive trust, credit vs. debit cards 


