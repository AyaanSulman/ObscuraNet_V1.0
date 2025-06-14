import socket
import threading
import logging
import time
import os
import json
import random
import base64

from cryptography.hazmat.primitives import serialization
from utils import get_local_ip, BUFFER_SIZE, scan_network
from crypto import (
    get_x25519_pubkey_b64,
    load_peer_x25519_pubkey_b64,
    derive_shared_key,
    chacha20_encrypt,
    chacha20_decrypt,
    load_fernet,
)
from pow import generate_pow_challenge, solve_pow, verify_pow_solution
from onion import peel_onion_envelope

logger = logging.getLogger(__name__)

POW_SESSION_FILE = "pow_sessions.json"
POW_TIMEOUT = 30  # seconds
PORT = 5000

_pow_sessions_lock = threading.Lock()
session_keys = {}  # { (peer_ip, my_pub_b64, peer_pub_b64): shared_key }


def load_pow_sessions():
    """
    Load PoW sessions from disk (encrypted by Fernet). Returns a dict { ip: last_timestamp }.
    """
    logger.debug("[network/load_pow_sessions] Entry")
    f_ = load_fernet()
    if os.path.exists(POW_SESSION_FILE):
        try:
            with open(POW_SESSION_FILE, "rb") as f_in:
                data = f_in.read()
            dec = f_.decrypt(data)
            sessions = json.loads(dec.decode())
            logger.info(f"[network/load_pow_sessions] Loaded sessions: {sessions}")
            return sessions
        except Exception as e:
            logger.error(f"[network/load_pow_sessions] Failed to load or decrypt: {e}")
            return {}
    logger.debug("[network/load_pow_sessions] No session file; starting fresh.")
    return {}


def save_pow_sessions(pow_sessions):
    """
    Save PoW sessions (timestamp by IP) to disk, encrypted by Fernet.
    """
    logger.debug("[network/save_pow_sessions] Entry")
    f_ = load_fernet()
    try:
        data = json.dumps(pow_sessions).encode()
        enc = f_.encrypt(data)
        with open(POW_SESSION_FILE, "wb") as f_out:
            f_out.write(enc)
        logger.info("[network/save_pow_sessions] Saved sessions to disk.")
    except Exception as e:
        logger.error(f"[network/save_pow_sessions] Failed to save sessions: {e}")


pow_sessions = load_pow_sessions()


def recvall(sock, n):
    """
    Read exactly n bytes from `sock`, blocking until all n arrive or socket closes.
    """
    logger.debug(f"[network/recvall] Entry: expecting {n} bytes")
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            logger.debug("[network/recvall] Connection closed while receiving.")
            return None
        data += packet
    logger.debug(f"[network/recvall] Received {len(data)} bytes.")
    return data


def handle_client(conn, addr):
    """
    Handle a newly accepted connection on `conn`.

    1) Try to see if the first message is b\"PUBKEY?\" within 2s.
       - If exactly b\"PUBKEY?\": reply with our base64 pubkey, close, and return.
       - If *any other non‐empty* data arrives: immediately log protocol‐mismatch, close, and return.
       - If *no* data arrives in 2s: treat that as a full handshake request.

    2) Full handshake:
       a) send OBNET_HELLO → expect OBNET_OK
       b) do PoW if needed → NOPROOF or challenge/solution
       c) ECDH: exchange X25519 pubkeys
       d) Enter loop receiving length‐prefixed blobs: first attempt onion peel, else decrypt JSON envelope.
    """
    logger.info(f"[network/handle_client] Connection from {addr}")
    conn.settimeout(2)

    # STEP 1: Peek for up to 2s to see if client sent exactly "PUBKEY?"
    try:
        data = conn.recv(BUFFER_SIZE)
        logger.debug(f"[network/handle_client] Initial data received: {data}")
    except socket.timeout:
        # No data in 2s → proceed to full handshake
        logger.debug("[network/handle_client] Initial recv timed out (no data). Proceeding to full handshake.")
        data = None
    except Exception as e:
        logger.error(f"[network/handle_client] Error on initial recv: {e}")
        conn.close()
        return

    # If client truly asked "PUBKEY?", do that shortcut and close
    if data and data.strip() == b"PUBKEY?":
        try:
            pubkey_b64 = get_x25519_pubkey_b64().encode() + b"\n"
            conn.sendall(pubkey_b64)
            logger.info(f"[network/handle_client] Responded to PUBKEY? from {addr}")
        except Exception as e:
            logger.error(f"[network/handle_client] Failed to send pubkey: {e}")
        finally:
            conn.close()
        return

    # If *any* other non‐empty data arrived, do *not* attempt handshake—just close (protocol mismatch)
    if data:
        logger.warning(f"[network/handle_client] Protocol mismatch (unexpected data: {data}), closing.")
        conn.close()
        return

    # STEP 2: Full handshake path (data is None, i.e. no initial bytes)
    conn.settimeout(None)
    try:
        conn.sendall(b"OBNET_HELLO")
        logger.debug("[network/handle_client] Sent OBNET_HELLO.")
    except Exception as e:
        logger.error(f"[network/handle_client] Failed to send OBNET_HELLO: {e}")
        conn.close()
        return

    try:
        resp = conn.recv(BUFFER_SIZE)
        logger.debug(f"[network/handle_client] Received after HELLO: {resp}")
    except Exception as e:
        logger.error(f"[network/handle_client] Error waiting for OBNET_OK: {e}")
        conn.close()
        return

    if not resp or resp.strip() != b"OBNET_OK":
        logger.warning("[network/handle_client] Protocol mismatch (no OBNET_OK), closing.")
        conn.close()
        return

    # STEP 3: PoW check
    sender_ip = addr[0]
    now = time.time()
    last = pow_sessions.get(sender_ip, 0)

    if now - last > POW_TIMEOUT:
        challenge, difficulty = generate_pow_challenge()
        payload = f"{challenge},{difficulty}".encode()
        try:
            conn.sendall(payload)
            logger.debug(f"[network/handle_client] Sent PoW challenge: {challenge},{difficulty}")
        except Exception as e:
            logger.error(f"[network/handle_client] Failed to send PoW challenge: {e}")
            conn.close()
            return

        time.sleep(1)
        try:
            solution = conn.recv(BUFFER_SIZE).decode().strip()
            logger.debug(f"[network/handle_client] Received PoW solution: {solution}")
        except Exception as e:
            logger.error(f"[network/handle_client] Failed to recv PoW solution: {e}")
            conn.close()
            return

        if not verify_pow_solution(challenge, difficulty, solution):
            logger.warning(f"[network/handle_client] Invalid PoW solution from {sender_ip}.")
            conn.close()
            return

        with _pow_sessions_lock:
            pow_sessions[sender_ip] = now
            save_pow_sessions(pow_sessions)
        logger.info(f"[network/handle_client] Accepted PoW from {sender_ip}.")
    else:
        try:
            conn.sendall(b"NOPROOF")
            logger.debug(f"[network/handle_client] Sent NOPROOF to {sender_ip}.")
        except Exception as e:
            logger.error(f"[network/handle_client] Failed to send NOPROOF: {e}")
            conn.close()
            return

    # STEP 4: ECDH Key Exchange
    try:
        my_pub_b64 = get_x25519_pubkey_b64().encode() + b"\n"
        conn.sendall(my_pub_b64)
        logger.debug("[network/handle_client] Sent X25519 public key.")
    except Exception as e:
        logger.error(f"[network/handle_client] Failed to send public key: {e}")
        conn.close()
        return

    try:
        peer_b64 = conn.recv(60).strip()
        logger.debug(f"[network/handle_client] Received peer public key: {peer_b64}")
        peer_pub_bytes = base64.b64decode(peer_b64)
    except Exception as e:
        logger.error(f"[network/handle_client] Failed to receive peer public key: {e}")
        conn.close()
        return

    try:
        shared_key = derive_shared_key(peer_pub_bytes)
        session_keys[(sender_ip,
                      my_pub_b64.decode().strip(),
                      peer_b64.decode().strip())] = shared_key
        logger.info(f"[network/handle_client] Derived shared key with {sender_ip}.")
    except Exception as e:
        logger.error(f"[network/handle_client] Key derivation failed: {e}")
        conn.close()
        return

    # STEP 5: Message‐loop (onion first, then non‐onion)
    while True:
        hdr = recvall(conn, 4)
        if not hdr:
            logger.debug("[network/handle_client] No length header; connection closing.")
            break
        msg_len = int.from_bytes(hdr, "big")
        logger.debug(f"[network/handle_client] Expecting encrypted blob of length {msg_len}")

        encrypted_blob = recvall(conn, msg_len)
        if not encrypted_blob:
            logger.debug("[network/handle_client] Failed to receive full encrypted blob; breaking.")
            break

        # --- Try onion layer first ---
        layer = peel_onion_envelope(encrypted_blob, shared_key)
        if layer:
            if "next_hop" in layer and "encrypted_payload" in layer:
                next_ip = layer["next_hop"]
                inner_blob = layer["encrypted_payload"]
                logger.info(f"[network/handle_client] Forwarding onion layer to {next_ip}")
                try:
                    s2, k2 = try_pow_handshake(next_ip)
                    if s2 and k2:
                        send_message(s2, inner_blob, k2, already_encrypted=True)
                        logger.debug(f"[network/handle_client] Onion fragment sent to {next_ip}")
                        s2.close()
                except Exception as fwd_err:
                    logger.error(f"[network/handle_client] Failed to forward onion: {fwd_err}")
                continue

            if "final_destination" in layer and "payload" in layer:
                msg = layer["payload"]
                logger.info(f"[ONION MESSAGE RECEIVED]: {msg}")
                print(f"[ONION MESSAGE RECEIVED]: {msg}")
                continue

        # --- Non‐onion fallback ---
        try:
            plaintext = chacha20_decrypt(encrypted_blob, shared_key)
            envelope = json.loads(plaintext.decode())
            my_ip = get_local_ip()
            dest = envelope.get("destination")
            hops_left = envelope.get("hops_left", 0)
            payload_msg = envelope.get("payload")

            if dest == my_ip:
                logger.info(f"[network/handle_client] Direct message for me: {payload_msg}")
                print(f"[MESSAGE RECEIVED]: {payload_msg}")

            elif hops_left > 0:
                envelope["hops_left"] = hops_left - 1
                logger.info(f"[network/handle_client] Forwarding non-onion to {dest} (hops_left→{hops_left-1})")
                forward_message(envelope, exclude_ip=sender_ip)
            else:
                logger.warning(f"[network/handle_client] Dropping packet from {sender_ip}, no hops left.")
        except Exception as e:
            logger.warning(f"[network/handle_client] Failed to decrypt/parse non-onion: {e}")
            continue

    conn.close()
    logger.debug("[network/handle_client] Connection closed.")
    return


def server_thread():
    """
    Listen on (my_IP, PORT) and spawn handle_client for each incoming connection.
    """
    host = get_local_ip()
    logger.info(f"[network/server_thread] Starting on {host}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, PORT))
        s.listen()
        logger.info(f"[network/server_thread] Listening on {host}:{PORT}")
    except Exception as e:
        logger.error(f"[network/server_thread] Bind/listen failed: {e}")
        return

    while True:
        try:
            conn, addr = s.accept()
            logger.info(f"[network/server_thread] Accepted connection from {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logger.error(f"[network/server_thread] Accept failed: {e}")


def try_pow_handshake(target_ip):
    """
    Attempt full PoW + ECDH handshake with peer at (target_ip, PORT).
    Returns (sock, shared_key) if successful, else (None, None).
    """
    logger.debug(f"[network/try_pow_handshake] Entry: target_ip={target_ip}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, PORT))
        logger.info(f"[network/try_pow_handshake] Connected to {target_ip}:{PORT}")
    except Exception as e:
        logger.error(f"[network/try_pow_handshake] TCP connect failed: {e}")
        return (None, None)

    try:
        greeting = s.recv(BUFFER_SIZE)
        logger.debug(f"[network/try_pow_handshake] Received greeting: {greeting}")
        if greeting != b"OBNET_HELLO":
            logger.warning("[network/try_pow_handshake] Not a valid ObscuraNet node.")
            s.close()
            return (None, None)
        s.sendall(b"OBNET_OK")
        logger.debug("[network/try_pow_handshake] Sent OBNET_OK")
    except Exception as e:
        logger.error(f"[network/try_pow_handshake] Error during HELLO/OK: {e}")
        s.close()
        return (None, None)

    # Wait a bit for PoW or NOPROOF
    time.sleep(0.1)
    try:
        data = s.recv(BUFFER_SIZE).decode().strip()
        logger.debug(f"[network/try_pow_handshake] After OBNET_OK, received: {data}")
        if data and data != "NOPROOF":
            parts = data.split(",")
            challenge = parts[0]
            difficulty = int(parts[1])
            logger.info(f"[network/try_pow_handshake] PoW challenge: {challenge},{difficulty}")
            sol = solve_pow(challenge, difficulty)
            s.sendall(sol.encode())
            logger.debug(f"[network/try_pow_handshake] Sent PoW solution: {sol}")
            time.sleep(2)
    except Exception as e:
        logger.error(f"[network/try_pow_handshake] PoW stage failed: {e}")
        s.close()
        return (None, None)

    # ECDH key exchange
    try:
        peer_b64 = s.recv(60).strip()
        logger.debug(f"[network/try_pow_handshake] Received peer pubkey: {peer_b64}")
        peer_pub_bytes = base64.b64decode(peer_b64)
    except Exception as e:
        logger.error(f"[network/try_pow_handshake] Failed to receive peer pubkey: {e}")
        s.close()
        return (None, None)

    try:
        my_pub_b64 = get_x25519_pubkey_b64().encode() + b"\n"
        s.sendall(my_pub_b64)
        logger.debug("[network/try_pow_handshake] Sent our X25519 pubkey.")
        shared_key = derive_shared_key(peer_pub_bytes)
        logger.info(f"[network/try_pow_handshake] Derived shared key with {target_ip}")
        return (s, shared_key)
    except Exception as e:
        logger.error(f"[network/try_pow_handshake] ECDH failed: {e}")
        s.close()
        return (None, None)


def send_message(sock, msg, shared_key, already_encrypted=False):
    """
    Send a length‐prefixed encrypted message over `sock` using `shared_key`.
    If already_encrypted=True, assume `msg` is raw ciphertext.
    """
    logger.debug(f"[network/send_message] Entry: already_encrypted={already_encrypted}")
    if not already_encrypted:
        if isinstance(msg, str):
            msg = msg.encode()
        try:
            encrypted = chacha20_encrypt(msg, shared_key)
            logger.debug(f"[network/send_message] Encrypted message length={len(encrypted)}")
        except Exception as e:
            logger.error(f"[network/send_message] Encryption failed: {e}")
            return
    else:
        encrypted = msg
        logger.debug(f"[network/send_message] Using pre‐encrypted blob, length={len(encrypted)}")

    length = len(encrypted).to_bytes(4, "big")
    try:
        sock.sendall(length + encrypted)
        logger.info("[network/send_message] Sent message blob.")
    except Exception as e:
        logger.error(f"[network/send_message] Send failed: {e}")


def forward_message(envelope, exclude_ip=None):
    """
    Forward a non-onion envelope to a random next hop (excluding exclude_ip and self).
    """
    logger.debug(f"[network/forward_message] Entry: envelope={envelope}, exclude_ip={exclude_ip}")
    peers = scan_network(PORT)
    candidates = [ip for ip in peers if ip != exclude_ip and ip != get_local_ip()]
    if not candidates:
        logger.warning("[network/forward_message] No available peers to forward.")
        return

    next_hop_ip = random.choice(candidates)
    logger.info(f"[network/forward_message] Chosen next hop: {next_hop_ip}")
    sock2, next_key = try_pow_handshake(next_hop_ip)
    if sock2:
        try:
            send_message(sock2, json.dumps(envelope).encode(), next_key)
            logger.info(f"[network/forward_message] Forwarded envelope to {next_hop_ip}")
        except Exception as e:
            logger.error(f"[network/forward_message] Failed to send to {next_hop_ip}: {e}")
        finally:
            sock2.close()


def get_peer_pubkey_b64(ip):
    """
    Fetch peer’s X25519 pubkey by sending “PUBKEY?” shortcut.
    Returns base64 string or None on failure.
    """
    logger.debug(f"[network/get_peer_pubkey_b64] Entry: ip={ip}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, PORT))
        logger.info(f"[network/get_peer_pubkey_b64] Connected to {ip}:{PORT}")

        s.sendall(b"PUBKEY?")
        logger.debug("[network/get_peer_pubkey_b64] Sent PUBKEY?")

        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(1)
            if not chunk:
                break
            data += chunk

        pubkey_b64 = data.strip().decode()
        logger.info(f"[network/get_peer_pubkey_b64] Received pubkey: {pubkey_b64[:10]}…")
        s.close()
        return pubkey_b64 if pubkey_b64 else None
    except Exception as e:
        logger.error(f"[network/get_peer_pubkey_b64] Failed to fetch pubkey from {ip}: {e}")
        return None
