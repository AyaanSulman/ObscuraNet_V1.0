import json
import base64
import logging
from crypto import chacha20_encrypt, chacha20_decrypt

logger = logging.getLogger(__name__)


def build_onion_envelope(route, session_keys, payload_dict):
    """
    Build a multi‐layered onion envelope from `route` and `payload_dict`.
    Each layer is encrypted with the corresponding session_keys.
    """
    logger.debug(f"[onion/build_onion_envelope] Entry: route={route}, payload={payload_dict}")
    # Start with the innermost payload (final hop)
    inner = {"final_destination": route[-1], "payload": payload_dict}
    inner_bytes = json.dumps(inner).encode()
    logger.debug("[onion/build_onion_envelope] Created innermost JSON payload.")

    # Wrap backwards through the intermediates
    for hop_ip in reversed(route[:-1]):
        data = {
            "next_hop": inner["final_destination"] if "final_destination" in inner else inner["next_hop"],
            "encrypted_payload": base64.b64encode(inner_bytes).decode(),
        }
        inner = data
        inner_bytes = json.dumps(data).encode()
        logger.debug(f"[onion/build_onion_envelope] Wrapped layer for hop {hop_ip}.")

    # Encrypt each layer in forward order
    onion_blob = inner_bytes
    for hop_ip in route:
        key = session_keys.get(hop_ip)
        if not key:
            logger.error(f"[onion/build_onion_envelope] Missing session key for {hop_ip}")
            raise ValueError(f"No session key for {hop_ip}")
        try:
            onion_blob = chacha20_encrypt(onion_blob, key)
            logger.debug(f"[onion/build_onion_envelope] Encrypted layer for {hop_ip}.")
        except Exception as e:
            logger.error(f"[onion/build_onion_envelope] Encryption failed at {hop_ip}: {e}")
            raise

    logger.info("[onion/build_onion_envelope] Completed onion envelope build.")
    return onion_blob


def peel_onion_envelope(encrypted_blob, session_key):
    """
    Attempt to decrypt one layer of the onion with `session_key`.
    Returns a dict with either {"next_hop": ip, "encrypted_payload": bytes}
    or {"final_destination": ip, "payload": {...}}. If decryption/parse fails, return None.
    """
    logger.debug(f"[onion/peel_onion_envelope] Entry: attempting to peel one layer.")
    try:
        decrypted = chacha20_decrypt(encrypted_blob, session_key)
        logger.debug("[onion/peel_onion_envelope] Decryption succeeded.")
    except Exception as e:
        logger.debug(f"[onion/peel_onion_envelope] Decryption failed: {e}")
        return None

    try:
        data = json.loads(decrypted.decode())
        logger.debug("[onion/peel_onion_envelope] JSON parse succeeded.")
    except Exception as e:
        logger.error(f"[onion/peel_onion_envelope] JSON parse failed: {e}")
        return None

    if data.get("encrypted_payload"):
        inner_bytes = base64.b64decode(data["encrypted_payload"].encode())
        next_hop = data["next_hop"]
        logger.info(f"[onion/peel_onion_envelope] Intermediate hop: next_hop={next_hop}")
        return {"next_hop": next_hop, "encrypted_payload": inner_bytes}

    if data.get("final_destination"):
        dest = data["final_destination"]
        payload = data["payload"]
        logger.info(f"[onion/peel_onion_envelope] Final destination reached: {dest}")
        return {"final_destination": dest, "payload": payload}

    logger.warning("[onion/peel_onion_envelope] Decrypted JSON missing expected keys.")
    return None
