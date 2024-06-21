import json
from scapy.all import sniff, Raw
from flask import Flask, jsonify

app = Flask(__name__)

# Dictionary to store the latest parsed values
latest_data = {}

def calculate_values(data):
    code = data[2]
    ab = round(data[3] / 92000, 2)
    qt = round((data[3] - data[27]) / 92000, 2)
    return code, ab, qt

def packet_callback(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if "POST /add_statinfo" in payload and "Content-Type: application/json" in payload:
            try:
                json_start = payload.find("[")
                json_end = payload.rfind("]") + 1
                json_data = json.loads(payload[json_start:json_end])
                for entry in json_data:
                    code, ab, qt = calculate_values(entry['data'])
                    latest_data['code'] = code
                    latest_data['ab'] = ab
                    latest_data['qt'] = qt
            except Exception as e:
                print(f"Error parsing JSON: {e}")

@app.route('/data', methods=['GET'])
def get_data():
    if latest_data:
        return jsonify(latest_data)
    else:
        return jsonify({"error": "No data found"}), 404

def start_sniffing():
    sniff(filter="tcp port 32999", prn=packet_callback, store=0)

if __name__ == '__main__':
    import threading
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    app.run(host='0.0.0.0', port=5000)
