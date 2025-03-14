# In collaboration with Clelia Jaye Molanda
import socket
import json
import struct
import pickle
import base64
import zlib
import threading
import time

XOR_KEY = 42

def xor_encrypt_decrypt(data):
    """Encrypts or decrypts data using XOR operation with proper encoding."""
    return ''.join(chr(ord(c) ^ XOR_KEY) for c in data)

# Physical Layer: Handles communication
class PhysicalLayer:
    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.received_data = None
        self.data_received_event = threading.Event()

    def start_server(self):
        """Starts a persistent socket server."""
        def server():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.host, self.port))
                s.listen()
                while True:
                    conn, _ = s.accept()
                    with conn:
                        self.received_data = conn.recv(4096).decode('utf-8')
                        self.data_received_event.set()
        
        threading.Thread(target=server, daemon=True).start()
    
    def send(self, data):
        """Sends data over a socket connection."""
        print(f"\n[Physical Layer] Sending raw data: {data}\n")
        time.sleep(1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(data.encode('utf-8'))
    
    def receive(self):
        """Waits until data is received."""
        self.data_received_event.wait()
        print(f"\n[Physical Layer] Received raw data: {self.received_data}\n")
        return self.received_data

# Data Link Layer: MAC Addressing
class DataLinkLayer:
    def __init__(self):
        self.mac_address = "AA:BB:CC:DD:EE:FF"
    
    def encapsulate(self, data):
        frame = json.dumps({"mac": self.mac_address, "data": data})
        print(f"[Data Link Layer] Encapsulated Frame: {frame}")
        return frame
    
    def decapsulate(self, frame):
        extracted_data = json.loads(frame)["data"]
        print(f"[Data Link Layer] Decapsulated Data: {extracted_data}")
        return extracted_data

# Network Layer: IP Routing
class NetworkLayer:
    def __init__(self):
        self.ip_address = "192.168.1.1"
    
    def route(self, data):
        packet = json.dumps({"ip": self.ip_address, "data": data})
        print(f"[Network Layer] Routed Packet: {packet}")
        return packet
    
    def receive(self, packet):
        extracted_data = json.loads(packet)["data"]
        print(f"[Network Layer] Received Packet Data: {extracted_data}")
        return extracted_data

# Transport Layer: Integrity Check
class TransportLayer:
    def segment(self, data):
        checksum = sum(bytearray(data, 'utf-8')) % 256
        segment = json.dumps({"seq": 1, "checksum": checksum, "data": data})
        print(f"[Transport Layer] Created Segment: {segment}")
        return segment
    
    def reassemble(self, segment):
        segment_data = json.loads(segment)
        checksum = sum(bytearray(segment_data["data"], 'utf-8')) % 256
        if checksum != segment_data["checksum"]:
            print("[Transport Layer] ERROR: Checksum mismatch!")
            return None
        print(f"[Transport Layer] Reassembled Data: {segment_data['data']}")
        return segment_data["data"]

# Session Layer: Session Control
class SessionLayer:
    def establish_session(self, data):
        session = json.dumps({"session": "active", "data": data})
        print(f"[Session Layer] Established Session: {session}")
        return session
    
    def terminate_session(self, session_data):
        extracted_data = json.loads(session_data)["data"]
        print(f"[Session Layer] Terminated Session, Extracted Data: {extracted_data}")
        return extracted_data

# Presentation Layer: Compression & Encryption
class PresentationLayer:
    def encode(self, data):
        compressed = zlib.compress(data.encode('utf-8'))
        encrypted = xor_encrypt_decrypt(base64.b64encode(compressed).decode('utf-8'))
        encoded = base64.b64encode(encrypted.encode('utf-8')).decode('utf-8')
        print(f"[Presentation Layer] Encoded Data: {encoded}")
        return encoded
    
    def decode(self, data):
        decrypted = xor_encrypt_decrypt(base64.b64decode(data).decode('utf-8'))
        decompressed = zlib.decompress(base64.b64decode(decrypted))
        decoded = decompressed.decode('utf-8')
        print(f"[Presentation Layer] Decoded Data: {decoded}")
        return decoded

# Application Layer: HTTP-like Messages
class ApplicationLayer:
    def request(self, message):
        request_data = f"HTTP REQUEST: {message}"
        print(f"[Application Layer] Created Request: {request_data}")
        return request_data
    
    def respond(self, request):
        response_data = f"HTTP RESPONSE: {request}"
        print(f"[Application Layer] Generated Response: {response_data}")
        return response_data

def simulate_osi_model():
    """Simulates the full OSI model with data transmission."""
    message = input("Enter your message: ")
    
    app_layer = ApplicationLayer()
    pres_layer = PresentationLayer()
    sess_layer = SessionLayer()
    trans_layer = TransportLayer()
    net_layer = NetworkLayer()
    data_link_layer = DataLinkLayer()
    phys_layer = PhysicalLayer()
    
    phys_layer.start_server()
    
    print("\n======= SENDING DATA =======")
    app_data = app_layer.request(message)
    encoded_data = pres_layer.encode(app_data)
    session_data = sess_layer.establish_session(encoded_data)
    segment_data = trans_layer.segment(session_data)
    packet_data = net_layer.route(segment_data)
    frame_data = data_link_layer.encapsulate(packet_data)
    phys_layer.send(frame_data)
    
    print("\n======= RECEIVING DATA =======")
    received_frame = phys_layer.receive()
    received_packet = data_link_layer.decapsulate(received_frame)
    received_segment = net_layer.receive(received_packet)
    received_session = trans_layer.reassemble(received_segment)
    
    if received_session:
        received_encoded = sess_layer.terminate_session(received_session)
        received_app_data = pres_layer.decode(received_encoded)
        response = app_layer.respond(received_app_data)
        print(f"\n======= FINAL RESPONSE =======\n{response}")

simulate_osi_model()
