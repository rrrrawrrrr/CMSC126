import socket
import json
import struct
import pickle
import base64

# Physical Layer: Handles bit-level transmission
class PhysicalLayer:
    def transmit(self, data):
        return ''.join(format(ord(i), '08b') for i in data)  # Convert to binary
    
    def receive(self, data):
        return ''.join(chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8))  # Convert back to text

# Data Link Layer: Adds/removes MAC address and frames
class DataLinkLayer:
    def __init__(self):
        self.mac_address = "AA:BB:CC:DD:EE:FF"
    
    def add_frame(self, data):
        return json.dumps({"mac": self.mac_address, "data": data})  # Add MAC address
    
    def remove_frame(self, frame):
        frame_data = json.loads(frame)
        return frame_data["data"]  # Extract data

# Network Layer: Adds/removes IP address and handles routing
class NetworkLayer:
    def __init__(self):
        self.ip_address = "192.168.1.1"
    
    def add_packet(self, data):
        return json.dumps({"ip": self.ip_address, "data": data})  # Add IP address
    
    def remove_packet(self, packet):
        packet_data = json.loads(packet)
        return packet_data["data"]  # Extract data

# Transport Layer: Implements TCP-like sequencing
class TransportLayer:
    def add_tcp_header(self, data):
        return json.dumps({"seq": 1, "data": data})  # Add sequence number
    
    def remove_tcp_header(self, segment):
        segment_data = json.loads(segment)
        return segment_data["data"]  # Extract data

# Session Layer: Manages connection states
class SessionLayer:
    def establish_session(self, data):
        return json.dumps({"session": "active", "data": data})  # Add session info
    
    def terminate_session(self, session_data):
        session_info = json.loads(session_data)
        return session_info["data"]  # Extract data

# Presentation Layer: Handles encoding and decoding
class PresentationLayer:
    def encode(self, data):
        return base64.b64encode(pickle.dumps(data)).decode('utf-8')  # Convert to base64 string
    
    def decode(self, data):
        return pickle.loads(base64.b64decode(data))  # Decode from base64

# Application Layer: Handles user interaction (simulating HTTP request/response)
class ApplicationLayer:
    def send_data(self, message):
        return f"HTTP REQUEST: {message}"
    
    def receive_data(self, response):
        return response.replace("HTTP RESPONSE: ", "")

# Simulation of data transmission
app_layer = ApplicationLayer()
presentation_layer = PresentationLayer()
session_layer = SessionLayer()
transport_layer = TransportLayer()
network_layer = NetworkLayer()
data_link_layer = DataLinkLayer()
physical_layer = PhysicalLayer()

# Sending Data
message = "Hello, Network!"
app_data = app_layer.send_data(message)  # Application layer processing
presentation_data = presentation_layer.encode(app_data)  # Encode data
session_data = session_layer.establish_session(presentation_data)  # Establish session
transport_data = transport_layer.add_tcp_header(session_data)  # Add TCP header
network_data = network_layer.add_packet(transport_data)  # Add IP packet
data_link_data = data_link_layer.add_frame(network_data)  # Add MAC frame
physical_data = physical_layer.transmit(data_link_data)  # Convert to binary

print("Data Transmitted over Network:", physical_data)

# Receiving Data
received_data = physical_layer.receive(physical_data)  # Convert back from binary
data_link_received = data_link_layer.remove_frame(received_data)  # Remove MAC frame
network_received = network_layer.remove_packet(data_link_received)  # Remove IP packet
transport_received = transport_layer.remove_tcp_header(network_received)  # Remove TCP header
session_received = session_layer.terminate_session(transport_received)  # Close session
presentation_received = presentation_layer.decode(session_received)  # Decode data
app_received = app_layer.receive_data(presentation_received)  # Extract message

print("Received Message:", app_received)
