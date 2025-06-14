import json
import threading
import time
import logging
import random
from utils import scan_network, get_local_ip, PORT
from network import (
    try_pow_handshake,
    send_message,
    server_thread,
    get_peer_pubkey_b64,
)
from routing import create_dummy_payload, routing_table, update_peer_status
from onion import build_onion_envelope
from crypto import (
    load_peer_x25519_pubkey_b64,
    derive_shared_key,
    get_x25519_pubkey_b64,
    load_peer_x25519_pubkey_b64,
    bootstrap_keys,
)
from cryptography.hazmat.primitives import serialization


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(levelname)s] %(message)s")

# Ensure root logger has at least one handler to show logs from all modules
if not logging.getLogger().handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logging.getLogger().addHandler(ch)


def dummy_sender_loop(sock, shared_key, stop_event):
    """
    Periodically send a dummy payload until stop_event is set.
    """
    logger.debug("[main/dummy_sender_loop] Entry")
    while not stop_event.is_set():
        interval = random.randint(10, 30)
        logger.info(f"[main/dummy_sender_loop] Sleeping {interval}s before next dummy")
        time.sleep(interval)
        payload = create_dummy_payload()
        try:
            send_message(sock, payload, shared_key, already_encrypted=False)
            logger.info("[main/dummy_sender_loop] Sent dummy payload.")
        except Exception as e:
            logger.error(f"[main/dummy_sender_loop] Failed to send dummy: {e}")


def client_loop():
    """
    1) Scan LAN for peers.
    2) Fetch pubkeys of newly discovered peers.
    3) Let user pick a peer (“rescan” or index).
    4) Perform PoW+ECDH handshake via try_pow_handshake.
    5) If connected:
         - Spawn a dummy‐sender thread.
         - Loop reading user messages (onion or non-onion).
         - Handle 'back' or 'quit'.
    """
    logger.debug("[main/client_loop] Entry")
    peer_pubkeys = {}
    self_ip = get_local_ip()

    while True:
        logger.debug("[main/client_loop] Scanning for peers")
        peers = scan_network(PORT)
        healthy_peers = [p for p in peers if routing_table.get(p, {}).get("score", 0) >= 0]
        logger.info(f"[main/client_loop] Discovered peers: {healthy_peers}")

        # Fetch pubkeys for any new peers
        for ip in healthy_peers:
            if ip not in peer_pubkeys:
                logger.debug(f"[main/client_loop] Fetching pubkey for {ip}")
                pk = get_peer_pubkey_b64(ip)
                if pk:
                    peer_pubkeys[ip] = pk
                    update_peer_status(ip, score=1)
                    logger.info(f"[main/client_loop] Cached pubkey for {ip}")

        # Display
        if not healthy_peers:
            print("No peers found; type 'rescan' to try again.")
        else:
            print("\nAvailable peers:")
            for idx, ip in enumerate(healthy_peers, 1):
                print(f"{idx}: {ip}")

        choice = input("Choose peer to connect (number) or 'rescan': ").strip()
        if choice.lower() == "rescan":
            continue

        try:
            idx = int(choice) - 1
            target_ip = healthy_peers[idx]
            logger.debug(f"[main/client_loop] User selected peer: {target_ip}")
        except Exception:
            print("Invalid choice.")
            continue

        logger.info(f"[main/client_loop] Attempting PoW handshake with {target_ip}")
        sock, shared_key = try_pow_handshake(target_ip)
        if not sock:
            logger.error("[main/client_loop] PoW handshake failed.")
            continue

        logger.info(f"[main/client_loop] Connected to {target_ip}. You may send messages.")
        stop_event = threading.Event()
        dummy_thread = threading.Thread(
            target=dummy_sender_loop, args=(sock, shared_key, stop_event), daemon=True
        )
        dummy_thread.start()
        logger.debug("[main/client_loop] Dummy sender thread started.")

        while True:
            msg = input("> You: ").strip()
            if msg.lower() == "quit":
                logger.info("[main/client_loop] User requested quit.")
                stop_event.set()
                dummy_thread.join()
                sock.close()
                return
            if msg.lower() == "back":
                logger.info("[main/client_loop] User requested back to peer list.")
                stop_event.set()
                dummy_thread.join()
                sock.close()
                break
            if not msg:
                continue

            dest = input("Destination IP (blank for direct): ").strip()
            if not dest:
                dest = target_ip
            logger.debug(f"[main/client_loop] Message destination set to {dest}")

            try:
                hops = int(input("How many hops (e.g. 2 or 3): ").strip())
            except Exception:
                hops = 2
            logger.debug(f"[main/client_loop] Hops chosen: {hops}")

            onion_mode = input("Use onion routing? (y/n): ").strip().lower() == "y"
            logger.debug(f"[main/client_loop] Onion mode: {onion_mode}")

            if not onion_mode:
                envelope = {"destination": dest, "hops_left": hops, "payload": msg}
                logger.debug(f"[main/client_loop] Sending non-onion envelope: {envelope}")
                send_message(sock, json.dumps(envelope).encode(), shared_key)
                logger.info("[main/client_loop] Non-onion message sent.")
            else:
                all_peers = [ip for ip in peer_pubkeys if ip != self_ip]
                logger.debug(f"[main/client_loop] Available peers for route: {all_peers}")

                if len(all_peers) >= hops:
                    cands = [p for p in all_peers if p != dest]
                    route = random.sample(cands, hops - 1)
                else:
                    cands = [p for p in all_peers if p != dest]
                    route = random.sample(cands, max(0, len(cands)))
                route.append(dest)
                logger.info(f"[main/client_loop] Onion route chosen: {route}")

                # Derive each hop's shared key
                session_map = {}
                for hop in route:
                    peer_b64 = peer_pubkeys[hop]
                    peer_pub = load_peer_x25519_pubkey_b64(peer_b64)
                    shared = derive_shared_key(peer_pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    ))
                    session_map[hop] = shared
                    logger.debug(f"[main/client_loop] Derived key for hop {hop}")

                payload_dict = {"message": msg, "from": self_ip}
                onion_blob = build_onion_envelope(route, session_map, payload_dict)
                logger.debug(f"[main/client_loop] Built onion blob size={len(onion_blob)}")
                send_message(sock, onion_blob, session_map[route[0]], already_encrypted=True)
                logger.info("[main/client_loop] Onion message sent.")

        # End of inner while (returned to peer list)



def main():
    """
    Entry point: bootstrap keys, start server thread, then enter client_loop.
    """
    logger.debug("[main/main] Entry")
    bootstrap_keys()

    server = threading.Thread(target=server_thread, daemon=True)
    server.start()
    logger.info("[main/main] Server thread started.")
    time.sleep(1)

    client_loop()
    logger.info("[main/main] Exiting application.")


if __name__ == "__main__":
    main()
