import socket
import logging

logger = logging.getLogger(__name__)
BUFFER_SIZE = 1024
PORT = 5000

def get_local_ip():
    """
    Return the LAN IP address by opening a UDP socket to 8.8.8.8.
    """
    logger.debug("[utils/get_local_ip] Entry")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        logger.debug(f"[utils/get_local_ip] Local IP detected: {ip}")
        return ip
    except Exception as e:
        logger.error(f"[utils/get_local_ip] Failed to determine local IP: {e}")
        return "127.0.0.1"
    finally:
        s.close()

def scan_network(port):
    """
    Scan the /24 LAN for peers listening on `port`.
    Returns a list of IPs that responded successfully (no data sent).
    """
    logger.debug(f"[utils/scan_network] Entry: scanning on port {port}")
    peers = []
    base_ip = get_local_ip().rsplit(".", 1)[0]  # e.g. "192.168.10"
    logger.debug(f"[utils/scan_network] Base subnet: {base_ip}.0/24")

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        if ip == get_local_ip():
            logger.debug(f"[utils/scan_network] Skipping self IP: {ip}")
            continue

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            logger.debug(f"[utils/scan_network] Trying connect {ip}:{port}")
            sock.connect((ip, port))
            # **Do not send any data here**—just testing open port.
            peers.append(ip)
            logger.info(f"[utils/scan_network] Found peer: {ip}")
        except Exception:
            logger.debug(f"[utils/scan_network] No response or port closed at {ip}:{port}")
        finally:
            sock.close()

    logger.debug(f"[utils/scan_network] Scan complete. Peers: {peers}")
    return peers
