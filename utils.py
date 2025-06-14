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

def scan_network(port, quick_mode=False):
    """
    Scan the /24 LAN for peers listening on `port`.
    Returns a list of IPs that responded successfully (no data sent).
    Set quick_mode=True to only scan a limited IP range (faster but less thorough).
    """
    logger.debug(f"[utils/scan_network] Entry: scanning on port {port}, quick_mode={quick_mode}")
    peers = []
    base_ip = get_local_ip().rsplit(".", 1)[0]  # e.g. "192.168.10"
    logger.debug(f"[utils/scan_network] Base subnet: {base_ip}.0/24")
    
    my_ip = get_local_ip()
    my_last_octet = int(my_ip.rsplit(".", 1)[1])
    
    # In quick mode, we only scan IPs close to our own IP + some common ranges
    if quick_mode:
        # Check IPs near our own (+/- 10)
        range_start = max(1, my_last_octet - 10)
        range_end = min(254, my_last_octet + 10)
        scan_ranges = [(range_start, range_end)]
        
        # Also check common IP ranges for devices
        common_ranges = [(1, 20), (100, 110), (192, 200), (250, 254)]
        for start, end in common_ranges:
            if not (start <= my_last_octet <= end):  # Avoid duplicate scanning
                scan_ranges.append((start, end))
    else:
        # Full scan of all IPs
        scan_ranges = [(1, 254)]

    try:
        for start, end in scan_ranges:
            for i in range(start, end + 1):
                ip = f"{base_ip}.{i}"
                if ip == my_ip:
                    logger.debug(f"[utils/scan_network] Skipping self IP: {ip}")
                    continue

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)  # Shorter timeout for quicker scans
                try:
                    logger.debug(f"[utils/scan_network] Trying connect {ip}:{port}")
                    sock.connect((ip, port))
                    # **Do not send any data here**—just testing open port
                    peers.append(ip)
                    logger.info(f"[utils/scan_network] Found peer: {ip}")
                except Exception:
                    pass  # Skip logging for cleaner output
                finally:
                    sock.close()
    except KeyboardInterrupt:
        logger.info("[utils/scan_network] Scan interrupted by user.")
    
    logger.debug(f"[utils/scan_network] Scan complete. Found {len(peers)} peers.")
    return peers
