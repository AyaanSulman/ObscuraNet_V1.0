# ObscuraNet

ObscuraNet is a cross-platform, privacy-focused peer-to-peer messaging protocol and reference implementation.  
It features robust end-to-end encrypted chat, Sybil/DoS resistance via Proof-of-Work, and advanced dummy traffic generation to foil surveillance and traffic analysis.

---

## Features

- **LAN Peer Discovery:** Nodes automatically discover peers on the local subnet via active scanning and secure protocol handshakes.
- **Sybil/Spam Protection:** Lightweight Proof-of-Work (PoW) challenge/response for every session, mitigating spam and Sybil attacks.
- **Per-Node Persistent X25519 Keys:** Each node has a unique, persistent X25519 keypair for Elliptic Curve Diffie-Hellman (ECDH) key exchange.
- **Session-Based ChaCha20 Encryption:** All chat and dummy messages are encrypted with ChaCha20-Poly1305 using a session key derived from X25519 ECDH.
- **Robust Message Framing:** Every message is length-prefixed to eliminate TCP fragmentation/boundary errors.
- **Indistinguishable Dummy Traffic:** Nodes generate random dummy packets, making traffic analysis and metadata profiling difficult.
- **Session and Key Management:** All keys are securely stored and loaded from disk for persistent node identity and secure operation across restarts.
- **Fernet for Local File Encryption:** Local JSON/config files (like PoW cache) are encrypted using Fernet for at-rest protection.
- **Cross-Platform:** Fully compatible with Linux (Kali) and Windows environments using Python 3.x.
- **Comprehensive Debug Logging:** Every handshake, connection, and cryptographic operation is logged for easy debugging and audit.

---

## How It Works

1. **Peer Discovery:**  
   Nodes scan the local subnet for ObscuraNet-compatible peers, connecting to nodes that complete the handshake and PoW.

2. **Session Bootstrap:**  
   Each connection requires a PoW challenge/response to authenticate the client and defend against spam or Sybil attacks.

3. **Key Exchange:**  
   Nodes exchange X25519 public keys after PoW. A shared session key is derived with ECDH (Curve25519), used for all further communication.

4. **Message Exchange:**  
   All chat and dummy messages are ChaCha20-Poly1305 encrypted using the session key. Each message is length-prefixed for robust framing.

5. **Dummy Traffic:**  
   At random intervals, nodes generate and send dummy packets, encrypted identically to real messages, making analysis of real communication much more difficult.

6. **Session and Key Management:**  
   Session and node keys are stored securely on disk. Fernet is used for local encryption of sensitive files like PoW session caches.

---

## Usage

### Requirements

- Python 3.8+ (Tested on Windows and Kali Linux)
- `cryptography` library

### Install Dependencies

```bash
pip install cryptography
````

### Run on Each Node

1. **Start the server and client interface** (runs automatically in the background):

   ```bash
   python main.py
   ```

2. **Scan for peers and connect:**

   * The CLI will display discovered peers. Select a peer to connect and start secure chat.
   * Type messages to send.
   * Type `quit` to exit, `back` to choose a new peer.

---

## Directory Structure

```
.
├── main.py
├── network.py
├── routing.py
├── crypto.py
├── pow.py
├── utils.py
└── keys/
    ├── x25519_private.key
    ├── x25519_public.key
    └── fernet.key
```

---

## Security Properties

* **Sybil-resistant:** Each session requires Proof-of-Work to prevent automated attacks.
* **End-to-end encryption:** All messages are ChaCha20-Poly1305 encrypted with session keys derived from X25519 ECDH.
* **Metadata and timing resistance:** Dummy traffic is generated continuously, blending with real traffic to defeat timing and metadata analysis.
* **Robust framing:** No TCP fragmentation or message boundary errors.
* **Key persistence:** Node identities and session caches persist across restarts. Fernet ensures sensitive files (like PoW caches) remain encrypted at rest.

---

## For Developers

* The codebase is fully modular; each protocol function is its own file.
* All core functions (keygen, PoW, session encryption, dummy logic) are easily reusable and extensible.
* Extensive debug statements included for all networking and crypto operations for fast troubleshooting.

---

## Future Work

* Onion routing and multi-hop message relay with per-hop layered ChaCha20 encryption.
* Adaptive dummy traffic rates and advanced traffic pattern shaping.
* Peer reputation and blacklisting.
* GUI interface for non-CLI users.
* Integration with post-quantum cryptography and advanced anonymity features.

---

## Academic/Report Summary

ObscuraNet implements a research-grade, SRS-aligned protocol for privacy-preserving, decentralized communication.
It features modern security primitives (PoW, X25519, ChaCha20), strong at-rest encryption (Fernet), and contemporary anti-analysis features, making it a reference both for education and real-world privacy-focused deployments.

---

## Authors

* M. Umair Shafiq (`251697475@formanite.fccollege.edu.pk`)
* M. Laraib Yazdani (`251707910@formanite.fccollege.edu.pk`)
* Ayaan Sulman (`251684910@formanite.fccollege.edu.pk`)
* Ali Abdul Aziz Bin Mansoor (`241560709@formanite.fccollege.edu.pk`)