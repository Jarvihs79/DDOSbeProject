from scapy.all import sniff
from flask import Flask, jsonify
from flask_cors import CORS
import threading
import datetime
from collections import deque
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Store packets in memory
packet_store = deque(maxlen=100)


def clean_protocol(proto):
    """Standardize protocol names"""
    proto = str(proto).strip().upper()
    if re.match(r'^(TCP|UDP|ICMP|HTTP|HTTPS|DNS|ARP|IP)$', proto):
        return proto
    return "Other"


def process_packet(packet):
    try:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")

        # Extract protocol with cleaning
        protocol = "Unknown"
        if packet.summary():
            protocol = clean_protocol(packet.summary().split()[0])

        # Extract source and destination
        src = "Unknown"
        dst = "Unknown"
        if hasattr(packet[0][1], 'src'):
            src = packet[0][1].src
        if hasattr(packet[0][1], 'dst'):
            dst = packet[0][1].dst

        packet_store.append({
            "timestamp": timestamp,
            "protocol": protocol,
            "src": src,
            "dst": dst,
            "size": len(packet)
        })
        logger.info(f"Processed packet from {src} to {dst} (Protocol: {protocol})")
    except Exception as e:
        logger.error(f"Error processing packet: {e}")


@app.route('/packets', methods=['GET'])
def get_packets():
    """Endpoint to retrieve captured packets"""
    try:
        # Validate packets before returning
        valid_packets = []
        for p in list(packet_store):
            if all(key in p for key in ['timestamp', 'protocol', 'size']):
                valid_packets.append(p)

        return jsonify({
            "status": "success",
            "packets": valid_packets
        })
    except Exception as e:
        logger.error(f"Error in /packets endpoint: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


def start_sniffing():
    """Start packet capture in background"""
    try:
        logger.info("Starting packet capture on all interfaces...")
        sniff(prn=process_packet, store=False)
    except Exception as e:
        logger.error(f"Packet capture failed: {e}")


if __name__ == '__main__':
    # Start packet capture in background thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    # Start Flask app
    logger.info("Starting Flask server on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)