from email.utils import parsedate_to_datetime
import socket
import struct
import threading
import logging
import random
import os
from collections import namedtuple

# Define the Header namedtuple matching the client's
Header = namedtuple('Header', ['version', 'type', 'window', 'seq_num', 'ack_num', 'checksum'])

# Packet types
SYN, SYN_ACK, ACK, DATA, FIN = range(5)

# Define the NetworkSimulator class to simulate packet loss
class NetworkSimulator:
    def __init__(self, loss_rate=0.1):
        self.loss_rate = loss_rate

    def should_drop(self):
        return random.random() < self.loss_rate

# Server class implementing the custom protocol
class ReliableServer:
    def __init__(self, host="127.0.0.1", port=8080, simulator=None):
        self.host = host
        self.port = port
        self.simulator = simulator or NetworkSimulator()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))

        # Client states to handle multiple clients
        self.client_states = {}

        # Logging
        logging.basicConfig(filename='server_protocol.log', level=logging.INFO)

    def start(self):
        print(f"Server started on {self.host}:{self.port}")
        while True:
            try:
                data, client_address = self.socket.recvfrom(4096)
                threading.Thread(target=self.handle_packet, args=(data, client_address)).start()
            except Exception as e:
                logging.error(f"Error receiving data: {e}")

    def handle_packet(self, data, client_address):
        try:
            header = self.parse_header(data)
            packet_type = header.type

            # Initialize client state if not present
            if client_address not in self.client_states:
                self.client_states[client_address] = {
                    'expected_seq_num': 0,
                    'connected': False,
                    'rwnd': 65535  # Receiver window size
                }

            client_state = self.client_states[client_address]

            if packet_type == SYN:
                self.handle_syn(header, client_address, client_state)
            elif packet_type == ACK:
                self.handle_ack(header, client_address, client_state)
            elif packet_type == DATA:
                self.handle_data(data, header, client_address, client_state)
            elif packet_type == FIN:
                self.handle_fin(header, client_address, client_state)
            else:
                logging.warning(f"Unknown packet type {packet_type} from {client_address}")
        except ValueError as ve:
            logging.error(f"Packet parsing error from {client_address}: {ve}")
        except Exception as e:
            logging.error(f"Error handling packet from {client_address}: {e}")

    def handle_syn(self, header, client_address, client_state):
        """Handle SYN packet for connection establishment."""
        logging.info(f"Received SYN from {client_address}")
        # Generate server's sequence number
        server_seq_num = random.randint(0, 2**32 - 1)
        client_state['server_seq_num'] = server_seq_num
        client_state['expected_seq_num'] = header.seq_num + 1

        # Create SYN-ACK packet
        syn_ack_pkt = self.create_packet(
            SYN_ACK,
            seq_num=server_seq_num,
            ack_num=client_state['expected_seq_num']
        )
        self.send_with_simulation(syn_ack_pkt, client_address)
        logging.info(f"Sent SYN-ACK to {client_address}")

    def handle_ack(self, header, client_address, client_state):
        """Handle ACK packet to complete connection establishment or data acknowledgment."""
        if not client_state['connected']:
            # Connection establishment phase
            if header.ack_num == client_state['server_seq_num'] + 1:
                client_state['connected'] = True
                client_state['expected_seq_num'] = header.seq_num
                client_state['server_seq_num'] += 1  # Increment server sequence number
                logging.info(f"Connection established with {client_address}")
            else:
                logging.warning(f"Unexpected ACK during connection setup from {client_address}")
        else:
            # Data transfer phase
            logging.info(f"Received ACK from {client_address}: {header.ack_num}")

    def handle_data(self, data, header, client_address, client_state):
        """Handle DATA packet during data transfer."""
        expected_seq_num = client_state['expected_seq_num']
        seq_num = header.seq_num
        data_payload = data[14:]  # Extract data after header

        if seq_num == expected_seq_num:
            # Correct packet received
            logging.info(f"Received DATA from {client_address}: seq_num={seq_num}")
            client_state['expected_seq_num'] += len(data_payload)
            # Process the data (e.g., save to file or handle as HTTP request)
            request = data_payload.decode('utf-8')
            response_content = self.handle_request(request)

            # Send ACK with updated ack_num
            ack_pkt = self.create_packet(
                ACK,
                seq_num=client_state['server_seq_num'],
                ack_num=client_state['expected_seq_num']
            )
            self.send_with_simulation(ack_pkt, client_address)
            logging.info(f"Sent ACK to {client_address}: ack_num={client_state['expected_seq_num']}")

            # Send response data back to the client
            if response_content:
                self.send_response(response_content, client_address, client_state)
        else:
            # Out-of-order packet, send duplicate ACK
            logging.warning(f"Out-of-order DATA from {client_address}: expected_seq_num={expected_seq_num}, received_seq_num={seq_num}")
            ack_pkt = self.create_packet(
                ACK,
                seq_num=client_state['server_seq_num'],
                ack_num=expected_seq_num
            )
            self.send_with_simulation(ack_pkt, client_address)
            logging.info(f"Sent duplicate ACK to {client_address}: ack_num={expected_seq_num}")

    def handle_fin(self, header, client_address, client_state):
        """Handle FIN packet for connection termination."""
        logging.info(f"Received FIN from {client_address}")
        # Send ACK for FIN
        fin_ack_pkt = self.create_packet(
            ACK,
            seq_num=client_state['server_seq_num'],
            ack_num=header.seq_num + 1
        )
        self.send_with_simulation(fin_ack_pkt, client_address)
        logging.info(f"Sent ACK for FIN to {client_address}")
        # Remove client state
        del self.client_states[client_address]
        logging.info(f"Connection closed with {client_address}")

    def send_response(self, response, client_address, client_state):
        """Send response data to the client using the custom protocol."""
        # Split response into segments
        segments = [response[i:i+1400] for i in range(0, len(response), 1400)]
        seq_num = client_state['server_seq_num']

        for segment in segments:
            data_pkt = self.create_packet(
                DATA,
                seq_num=seq_num,
                ack_num=client_state['expected_seq_num'],
                data=segment.encode('utf-8')
            )
            self.send_with_simulation(data_pkt, client_address)
            logging.info(f"Sent DATA to {client_address}: seq_num={seq_num}")
            seq_num += len(segment)

        # Update server sequence number
        client_state['server_seq_num'] = seq_num

        # Send FIN packet to signal end of data
        fin_pkt = self.create_packet(
            FIN,
            seq_num=client_state['server_seq_num'],
            ack_num=client_state['expected_seq_num']
        )
        self.send_with_simulation(fin_pkt, client_address)
        logging.info(f"Sent FIN to {client_address}")

    def create_packet(self, type, seq_num=0, ack_num=0, data=b''):
        """Create a packet with the given parameters."""
        header = Header(
            version=1,
            type=type,
            window=65535,  # Server's receive window size
            seq_num=seq_num,
            ack_num=ack_num,
            checksum=0
        )
        header_bytes = struct.pack('!BBHLLH', *header)
        packet = header_bytes + data

        # Calculate checksum
        checksum = self.calculate_checksum(packet)
        # Insert checksum into the packet
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]
        return packet

    def calculate_checksum(self, packet):
        """Calculate checksum for the given packet."""
        # Zero out checksum field for calculation
        packet_zero_checksum = packet[:12] + b'\x00\x00' + packet[14:]
        checksum = sum(packet_zero_checksum) & 0xFFFF
        return checksum

    def parse_header(self, packet):
        """Parse the header of the received packet."""
        if len(packet) < 14:
            raise ValueError("Packet too short")
        header = Header._make(struct.unpack('!BBHLLH', packet[:14]))
        # Verify checksum
        received_checksum = header.checksum
        calculated_checksum = self.calculate_checksum(packet)
        if received_checksum != calculated_checksum:
            raise ValueError("Checksum mismatch")
        return header

    def send_with_simulation(self, packet, client_address):
        """Send packet to client with simulated packet loss."""
        if not self.simulator.should_drop():
            self.socket.sendto(packet, client_address)
            logging.info(f"Sent packet to {client_address}: {self.parse_header(packet)}")
        else:
            logging.info(f"Dropped packet to {client_address}: {self.parse_header(packet)}")

    def handle_request(self, request):
        """Handle the HTTP request from the client."""
        try:
            headers = request.split("\r\n")
            request_line = headers[0].split()

            if len(request_line) < 3:
                return HTTP_RESPONSES[400]

            method, path, protocol = request_line
            if not path or not len(path): 
                return HTTP_RESPONSES[400]
            
            path = path.lstrip("/")
            if path != "test.html": 
                logging.info(HTTP_RESPONSES[404])
                return HTTP_RESPONSES[404]

            if method in ["HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]:
                return HTTP_RESPONSES[501]

            logging.info(f"PATH {path}")
            if method == "GET":
                if path == "test.html":
                    if_modified_since = None
                    for header in headers[1:]:
                        if header.lower().startswith("if-modified-since:"):
                            if_modified_since = header.split(":", 1)[1].strip()
                            break

                    if not os.path.exists(path):
                        return HTTP_RESPONSES[404]

                    if if_modified_since:
                        ims_timestamp = parse_http_date(if_modified_since)
                        last_modified_timestamp = parse_http_date(LAST_MODIFIED)
                        
                        if ims_timestamp and last_modified_timestamp:
                            if ims_timestamp >= last_modified_timestamp:
                                logging.info("304 Not Modified: Resource not modified since " + if_modified_since)
                                return HTTP_RESPONSES[304]

                    with open(path, 'r') as file:
                        content = file.read()
                    return HTTP_RESPONSES[200].format(LAST_MODIFIED) + content
                else:
                    return HTTP_RESPONSES[404]
            else:
                return HTTP_RESPONSES[400]
        
        except Exception as e:
            logging.error(f"Error handling request: {e}")
            return HTTP_RESPONSES[400]

def parse_http_date(date_string):
    """Parse HTTP date string to timestamp."""
    if date_string:
        try:
            return parsedate_to_datetime(date_string).timestamp()
        except ValueError:
            logging.error(f"Invalid date format: {date_string}")
    return None

# HTTP response templates
LAST_MODIFIED = "Sat, 21 Oct 2024 00:00:00 GMT"

HTTP_RESPONSES = {
    200: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nLast-Modified: {}\r\n\r\n",
    204: "HTTP/1.1 204 No Content\r\n\r\n",
    304: "HTTP/1.1 304 Not Modified\r\n\r\n",
    400: "HTTP/1.1 400 Bad Request\r\n\r\n",
    404: "HTTP/1.1 404 Not Found\r\n\r\n",
    501: "HTTP/1.1 501 Not Implemented\r\n\r\n",
}

if __name__ == "__main__":
    server = ReliableServer()
    server.start()