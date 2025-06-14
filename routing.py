import time
import json
import random
import logging
from crypto import load_fernet

logger = logging.getLogger(__name__)

# In‐memory table: { ip_str: { "score": int, "last_seen": float(timestamp) } }
routing_table = {}


def update_peer_status(ip, score=1):
    """
    Insert or update an entry in routing_table. Update last_seen to now.
    """
    logger.debug(f"[routing/update_peer_status] Entry: ip={ip}, score={score}")
    routing_table[ip] = {"score": score, "last_seen": time.time()}
    logger.info(f"[routing/update_peer_status] Updated {ip} → {routing_table[ip]}")


def is_dummy_message(msg: bytes):
    """
    Check whether `msg` is a dummy payload by attempting a Fernet decrypt.
    """
    logger.debug("[routing/is_dummy_message] Entry")
    f = load_fernet()
    try:
        payload = json.loads(msg)
        token = payload.get("dummy", "")
        if not token:
            logger.debug("[routing/is_dummy_message] No 'dummy' key found.")
            return False
        f.decrypt(token.encode())
        logger.info("[routing/is_dummy_message] Detected dummy message.")
        return True
    except Exception as e:
        logger.debug(f"[routing/is_dummy_message] Not a dummy: {e}")
        return False


def create_dummy_payload():
    """
    Create a JSON‐encoded dummy payload with a Fernet‐encrypted tag.
    """
    logger.debug("[routing/create_dummy_payload] Entry")
    f = load_fernet()
    try:
        tag = f.encrypt(b"DUMMY").decode()
        payload = {"dummy": tag}
        enc = json.dumps(payload).encode()
        logger.info("[routing/create_dummy_payload] Dummy payload created.")
        return enc
    except Exception as e:
        logger.error(f"[routing/create_dummy_payload] Failed to create dummy payload: {e}")
        raise


def select_healthy_peer(peers):
    """
    Choose one peer from `peers` whose score > 0. If none, random from all.
    """
    logger.debug(f"[routing/select_healthy_peer] Entry: peers={peers}")
    healthy = [p for p in peers if routing_table.get(p, {}).get("score", 0) > 0]
    if healthy:
        choice = random.choice(healthy)
        logger.info(f"[routing/select_healthy_peer] Selected healthy peer: {choice}")
        return choice
    if peers:
        choice = random.choice(peers)
        logger.info(f"[routing/select_healthy_peer] No healthy peers; selected random: {choice}")
        return choice
    logger.warning("[routing/select_healthy_peer] No peers available to select.")
    return None
