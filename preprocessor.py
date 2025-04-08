from collections import defaultdict
import datetime
import threading
import numpy as np
import requests
import time


class FlowProcessor:
    def __init__(self, window=5):  # Increased window to 5 seconds
        self.window = window
        self.flows = defaultdict(list)
        self.lock = threading.Lock()
        self.timer = None
        print("Preprocessor initialized!")

    def start(self):
        self._schedule()

    def _schedule(self):
        self.timer = threading.Timer(self.window, self._process_flows)
        self.timer.daemon = True
        self.timer.start()

    def _fetch_packets(self):
        try:
            response = requests.get("http://localhost:5000/packets", timeout=2)
            if response.status_code == 200:
                return response.json().get('packets', [])
        except:
            return []
        return []

    def _process_flows(self):
        # Fetch packets from sniffer
        packets = self._fetch_packets()
        print(f"Fetched {len(packets)} packets from sniffer")

        # Group packets into flows
        for packet in packets:
            flow_key = (packet['src'], packet['dst'], packet['protocol'])
            with self.lock:
                self.flows[flow_key].append(packet)

        # Process flows
        features = []
        for key, flow_packets in self.flows.items():
            if len(flow_packets) < 2:
                continue

            # Feature extraction
            sizes = [p['size'] for p in flow_packets]
            timestamps = [datetime.datetime.strptime(p['timestamp'], "%H:%M:%S.%f") for p in flow_packets]
            duration = (max(timestamps) - min(timestamps)).total_seconds()

            features.append([
                len(flow_packets),  # Packet count
                sum(sizes),  # Total bytes
                np.mean(sizes),  # Avg packet size
                duration,  # Flow duration
                len(flow_packets) / max(duration, 1),  # Packet rate
                sum(sizes) / max(duration, 1)  # Byte rate
            ])

        # Send to inference API
        if features:
            print(f"Sending {len(features)} feature sets to inference")
            try:
                response = requests.post(
                    "http://localhost:5001/predict",
                    json={'features': features},
                    timeout=2
                )
                print(f"Inference response: {response.status_code}")
            except Exception as e:
                print(f"Failed to send to inference API: {e}")

        # Reset flows
        with self.lock:
            self.flows.clear()

        self._schedule()


if __name__ == '__main__':
    processor = FlowProcessor()
    processor.start()
    while True:  # Keep the processor running
        time.sleep(1)