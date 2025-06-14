import json
import threading
import time
import logging
import random
import os
import sys
import signal
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


# Terminal colors for better CLI experience
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(levelname)s] %(message)s")

# Ensure root logger has at least one handler to show logs from all modules
if not logging.getLogger().handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logging.getLogger().addHandler(ch)

# Global flag to signal graceful shutdown
stop_event = threading.Event()


# Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    print(f"\n{Colors.WARNING}[*] Shutting down ObscuraNet gracefully...{Colors.ENDC}")
    stop_event.set()
    # Give a moment for threads to clean up
    time.sleep(1)
    sys.exit(0)


# Register signal handler
signal.signal(signal.SIGINT, signal_handler)


def dummy_sender_loop(sock, shared_key, local_stop_event):
    """
    Periodically send a dummy payload until stop_event is set.
    """
    logger.debug("[main/dummy_sender_loop] Entry")
    while not local_stop_event.is_set() and not stop_event.is_set():
        interval = random.randint(10, 30)
        logger.info(f"[main/dummy_sender_loop] Sleeping {interval}s before next dummy")
        
        # Check stop_event every second instead of sleeping for the whole interval
        for _ in range(interval):
            if local_stop_event.is_set() or stop_event.is_set():
                break
            time.sleep(1)
            
        if local_stop_event.is_set() or stop_event.is_set():
            break
            
        payload = create_dummy_payload()
        try:
            send_message(sock, payload, shared_key, already_encrypted=False)
            logger.info("[main/dummy_sender_loop] Sent dummy payload.")
        except Exception as e:
            logger.error(f"[main/dummy_sender_loop] Failed to send dummy: {e}")
            # If we can't send messages, the connection is likely broken
            break
    
    logger.debug("[main/dummy_sender_loop] Exiting dummy sender loop.")



def print_banner():
    """
    Display a welcome banner for the ObscuraNet client.
    """
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║ {Colors.BOLD}ObscuraNet P2P Secure Messaging{Colors.ENDC}{Colors.CYAN}                        ║
║ {Colors.BLUE}Decentralized, Encrypted, Private{Colors.CYAN}                         ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)


def print_help():
    """
    Display available commands and their descriptions.
    """
    help_text = f"""
{Colors.CYAN}═══════════════════════ {Colors.BOLD}AVAILABLE COMMANDS{Colors.ENDC}{Colors.CYAN} ═══════════════════════{Colors.ENDC}

{Colors.GREEN}Basic Commands:{Colors.ENDC}
  {Colors.BOLD}rescan{Colors.ENDC}       - Scan the network for new peers
  {Colors.BOLD}quickscan{Colors.ENDC}    - Perform a faster scan of common IP ranges
  {Colors.BOLD}help{Colors.ENDC}         - Display this help message
  {Colors.BOLD}quit{Colors.ENDC}         - Exit ObscuraNet
  {Colors.BOLD}<number>{Colors.ENDC}      - Connect to the peer with this number

{Colors.GREEN}When Connected to a Peer:{Colors.ENDC}
  {Colors.BOLD}back{Colors.ENDC}         - Return to the peer selection menu
  {Colors.BOLD}direct{Colors.ENDC}       - Send a direct message (no onion routing)
  {Colors.BOLD}onion{Colors.ENDC}        - Send a message via onion routing (anonymous)
  """
    print(help_text)


def client_loop():
    """
    Improved CLI: Always show available commands after peer scan and after returning from a peer session. Add color to peer list and prompts. Handle 'quickscan' and 'help'. Make 'back' and 'quit' robust.
    """
    logger.debug("[main/client_loop] Entry")
    peer_pubkeys = {}
    self_ip = get_local_ip()

    while True:
        print_banner()
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
            print(f"{Colors.WARNING}No peers found; type 'rescan' or 'quickscan' to try again.{Colors.ENDC}")
        else:
            print(f"\n{Colors.GREEN}Available peers:{Colors.ENDC}")
            for idx, ip in enumerate(healthy_peers, 1):
                print(f"  {Colors.BOLD}{idx}{Colors.ENDC}: {Colors.BLUE}{ip}{Colors.ENDC}")

        print_help()  # Always show commands

        choice = input(f"{Colors.CYAN}Choose peer (number), or command: {Colors.ENDC}").strip()
        if choice.lower() == "rescan":
            continue
        if choice.lower() == "quickscan":
            print(f"{Colors.CYAN}Performing quick scan...{Colors.ENDC}")
            peers = scan_network(PORT, quick_mode=True)
            healthy_peers = [p for p in peers if routing_table.get(p, {}).get("score", 0) >= 0]
            continue
        if choice.lower() == "help":
            print_help()
            continue
        if choice.lower() == "quit":
            print(f"{Colors.WARNING}Exiting ObscuraNet...{Colors.ENDC}")
            sys.exit(0)

        try:
            idx = int(choice) - 1
            target_ip = healthy_peers[idx]
            logger.debug(f"[main/client_loop] User selected peer: {target_ip}")
        except Exception:
            print(f"{Colors.FAIL}Invalid choice.{Colors.ENDC}")
            continue

        logger.info(f"[main/client_loop] Attempting PoW handshake with {target_ip}")
        sock, shared_key = try_pow_handshake(target_ip)
        if not sock:
            logger.error("[main/client_loop] PoW handshake failed.")
            print(f"{Colors.FAIL}PoW handshake failed. Peer may be offline or unreachable.{Colors.ENDC}")
            continue

        print(f"{Colors.GREEN}Connected to {target_ip}. Type 'back' to return to peer list, or 'quit' to exit.{Colors.ENDC}")
        local_stop_event = threading.Event()
        dummy_thread = threading.Thread(
            target=dummy_sender_loop, args=(sock, shared_key, local_stop_event), daemon=True
        )
        dummy_thread.start()
        logger.debug("[main/client_loop] Dummy sender thread started.")

        while True:
            msg = input(f"{Colors.BOLD}> You:{Colors.ENDC} ").strip()
            if msg.lower() == "quit":
                logger.info("[main/client_loop] User requested quit.")
                local_stop_event.set()
                dummy_thread.join()
                sock.close()
                print(f"{Colors.WARNING}Exiting ObscuraNet...{Colors.ENDC}")
                sys.exit(0)
            if msg.lower() == "back":
                logger.info("[main/client_loop] User requested back to peer list.")
                local_stop_event.set()
                dummy_thread.join()
                sock.close()
                print(f"{Colors.CYAN}Returning to peer list...{Colors.ENDC}")
                break
            if msg.lower() == "help":
                print_help()
                continue
            if not msg:
                continue

            dest = input(f"{Colors.CYAN}Destination IP (blank for direct): {Colors.ENDC}").strip()
            if not dest:
                dest = target_ip
            logger.debug(f"[main/client_loop] Message destination set to {dest}")

            try:
                hops = int(input(f"{Colors.CYAN}How many hops (e.g. 2 or 3): {Colors.ENDC}").strip())
            except Exception:
                hops = 2
            logger.debug(f"[main/client_loop] Hops chosen: {hops}")

            onion_mode = input(f"{Colors.CYAN}Use onion routing? (y/n): {Colors.ENDC}").strip().lower() == "y"
            logger.debug(f"[main/client_loop] Onion mode: {onion_mode}")

            if not onion_mode:
                envelope = {"destination": dest, "hops_left": hops, "payload": msg}
                logger.debug(f"[main/client_loop] Sending non-onion envelope: {envelope}")
                send_message(sock, json.dumps(envelope).encode(), shared_key)
                logger.info("[main/client_loop] Non-onion message sent.")
            else:
                all_peers = [ip for ip in peer_pubkeys if ip != self_ip]
                logger.debug(f"[main/client_loop] Available peers for route: {all_peers}")

                if len(all_peers) < hops:
                    print(f"{Colors.WARNING}Warning: Requested {hops} hops, but only {len(all_peers)} peers are available. Reducing hops to {len(all_peers)}.{Colors.ENDC}")
                    hops = len(all_peers)
                    if hops == 0:
                        print(f"{Colors.FAIL}No available peers for onion routing!{Colors.ENDC}")
                        continue
                cands = [p for p in all_peers if p != dest]

                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        if len(cands) >= hops - 1:
                            route = random.sample(cands, hops - 1)
                        else:
                            route = random.sample(cands, max(0, len(cands)))
                        route.append(dest)
                        logger.info(f"[main/client_loop] Onion route chosen (attempt {attempt+1}): {route}")

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
                        break
                    except Exception as e:
                        logger.error(f"[main/client_loop] Failed to send via route {route}: {e}")
                        print(f"{Colors.WARNING}Failed to send message via selected route. Retrying with a new route...{Colors.ENDC}")
                        time.sleep(1)
                else:
                    print(f"{Colors.FAIL}All attempts to send onion message failed!{Colors.ENDC}")

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
