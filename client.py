import socket
import struct
import random
import time
import logging
from collections import namedtuple

Header = namedtuple('Header', ['version', 'type', 'window', 'seq_num', 'ack_num', 'checksum'])

# Simplified packet types
SYN, SYN_ACK, ACK, DATA, FIN = range(5)

class NetworkSimulator:
    def __init__(self, loss_rate=0.1):
        self.loss_rate = loss_rate
        
    def should_drop(self):
        return random.random() < self.loss_rate

class ReliableProtocol:
    def __init__(self, host, port, simulator=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(1.5)  # 1 second timeout
        self.host = host
        self.port = port
        self.simulator = simulator or NetworkSimulator()
        
        # Basic state
        self.seq_num = random.randint(0, 2**32 - 1)
        self.expected_seq_num = 0
        self.connected = False
        
        # Flow and congestion control
        self.cwnd = 1      # Congestion window (in segments)
        self.ssthresh = 16 # Slow start threshold
        self.rwnd = 65535  # Receiver window
        
        # Buffers
        self.send_buffer = {}
        self.recv_buffer = {}
        
        # Logging
        logging.basicConfig(filename='client_protocol.log', level=logging.INFO)
    
    def create_packet(self, type, data=b''):
        header = Header(
            version=1,
            type=type,
            window=self.rwnd,
            seq_num=self.seq_num,
            ack_num=self.expected_seq_num,
            checksum=0
        )
        header_bytes = struct.pack('!BBHLLH', *header)
        packet = header_bytes + data

        # Zero out checksum field for calculation
        packet_zero_checksum = packet[:12] + b'\x00\x00' + packet[14:]

        # Calculate checksum
        checksum = sum(packet_zero_checksum) & 0xFFFF

        # Insert checksum into the packet
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]

        return packet
    
    def send_with_simulation(self, packet, addr):
        header = self.parse_header(packet)
        if not self.simulator.should_drop():
            self.socket.sendto(packet, addr)
            logging.info(f"Sent packet to {addr}: type={header.type}, seq_num={header.seq_num}, ack_num={header.ack_num}")
        else:
            logging.info(f"Dropped packet to {addr}: type={header.type}, seq_num={header.seq_num}, ack_num={header.ack_num}")
    
    def establish_connection(self):
        """Three-way handshake with retries"""
        syn_pkt = self.create_packet(SYN)
        attempts = 0
        max_attempts = 5

        while attempts < max_attempts:
            self.send_with_simulation(syn_pkt, (self.host, self.port))
            logging.info(f"Sent SYN with seq_num={self.seq_num}")
            try:
                data, addr = self.socket.recvfrom(1500)
                header = self.parse_header(data)
                if header.type == SYN_ACK and header.ack_num == self.seq_num + 1:
                    logging.info(f"Received SYN-ACK from server with seq_num={header.seq_num}, ack_num={header.ack_num}")
                    # Update sequence numbers
                    self.seq_num += 1
                    self.expected_seq_num = header.seq_num + 1
                    ack_pkt = self.create_packet(ACK)
                    self.send_with_simulation(ack_pkt, addr)
                    logging.info(f"Sent ACK with seq_num={self.seq_num}, ack_num={self.expected_seq_num}")
                    self.connected = True
                    return
                else:
                    logging.warning("Unexpected packet during handshake")
            except socket.timeout:
                attempts += 1
                logging.warning(f"Timeout waiting for SYN-ACK, attempt {attempts}/{max_attempts}")
        raise Exception("Connection failed after maximum retries")
    
    def send_data(self, data):
        """Send data using sliding window"""
        if not self.connected:
            raise Exception("Not connected")
        
        segments = [data[i:i+1400] for i in range(0, len(data), 1400)]
        base_seq = self.seq_num
        next_seq = self.seq_num
        acked_seq = self.seq_num
        window = {}  # Keep track of sent but unacknowledged packets
        timers = {}
        timeout_interval = 1.0  # Adjust as necessary

        while acked_seq < base_seq + len(data):
            # Send packets within the congestion window
            while (next_seq - acked_seq) < self.cwnd * 1400 and (next_seq - base_seq) < len(data):
                segment_index = (next_seq - base_seq) // 1400
                segment = segments[segment_index]
                packet = self.create_packet(DATA, segment)
                self.send_with_simulation(packet, (self.host, self.port))
                logging.info(f"Sent DATA with seq_num={self.seq_num}")
                window[self.seq_num] = packet
                timers[self.seq_num] = time.time()
                next_seq += len(segment)
                self.seq_num += len(segment)
            
            try:
                data, addr = self.socket.recvfrom(1500)
                header = self.parse_header(data)
                if header.type == ACK:
                    logging.info(f"Received ACK with ack_num={header.ack_num}")
                    ack_num = header.ack_num
                    if ack_num > acked_seq:
                        # New acknowledgment received
                        acked_seq = ack_num
                        # Remove acknowledged packets from window and timers
                        keys_to_remove = [seq for seq in window if seq < acked_seq]
                        for seq in keys_to_remove:
                            del window[seq]
                            del timers[seq]
                        # Update congestion window
                        if self.cwnd < self.ssthresh:
                            self.cwnd += 1  # Slow start
                        else:
                            self.cwnd += 1 / self.cwnd  # Congestion avoidance
                    else:
                        logging.warning(f"Received duplicate ACK with ack_num={header.ack_num}")
            except socket.timeout:
                # Check for timeouts
                current_time = time.time()
                for seq in list(timers):
                    if current_time - timers[seq] > timeout_interval:
                        # Timeout occurred, retransmit packet
                        logging.warning(f"Timeout for seq_num={seq}, retransmitting")
                        packet = window[seq]
                        self.send_with_simulation(packet, (self.host, self.port))
                        timers[seq] = current_time
                        # Adjust congestion window
                        self.ssthresh = max(self.cwnd // 2, 1)
                        self.cwnd = 1
    
    def receive_data(self):
        """Receive data from the server"""
        received_data = b''
        original_timeout = self.socket.gettimeout()
        self.socket.settimeout(5.0)  # Increase timeout during data reception
        while True:
            try:
                data, addr = self.socket.recvfrom(1500)
                header = self.parse_header(data)
                if header.type == DATA:
                    logging.info(f"Received DATA from server with seq_num={header.seq_num}")
                    if header.seq_num == self.expected_seq_num:
                        # Correct packet received
                        data_payload = data[14:]  # Extract data after header
                        received_data += data_payload
                        self.expected_seq_num += len(data_payload)
                        # Send ACK
                        ack_pkt = self.create_packet(ACK)
                        self.send_with_simulation(ack_pkt, addr)
                        logging.info(f"Sent ACK with ack_num={self.expected_seq_num}")
                    else:
                        # Out-of-order packet, send duplicate ACK
                        logging.warning(f"Out-of-order DATA received. Expected seq_num={self.expected_seq_num}, got seq_num={header.seq_num}")
                        ack_pkt = self.create_packet(ACK)
                        self.send_with_simulation(ack_pkt, addr)
                elif header.type == FIN:
                    # Connection termination
                    logging.info("Received FIN from server")
                    # Send ACK for FIN
                    fin_ack_pkt = self.create_packet(ACK)
                    self.send_with_simulation(fin_ack_pkt, addr)
                    logging.info("Sent ACK for FIN")
                    break
            except socket.timeout:
                logging.warning("Timeout while waiting for data")
                break
        self.socket.settimeout(original_timeout)  # Reset timeout
        return received_data
    
    def parse_header(self, packet):
        """Parse packet header and verify checksum"""
        if len(packet) < 14:
            raise ValueError("Packet too short")
        header = Header._make(struct.unpack('!BBHLLH', packet[:14]))

        # Verify checksum
        received_checksum = header.checksum
        packet_zero_checksum = packet[:12] + b'\x00\x00' + packet[14:]
        calculated_checksum = sum(packet_zero_checksum) & 0xFFFF
        if received_checksum != calculated_checksum:
            raise ValueError("Checksum mismatch")
        return header

def run_test():
    """Run basic test with simulated losses"""
    simulator = NetworkSimulator(loss_rate=0.1)
    protocol = ReliableProtocol('localhost', 8080, simulator)
    
    try:
        protocol.establish_connection()
        logging.info("Connection established")
        
        # Send HTTP GET request
        http_request = "GET /test.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
        protocol.send_data(http_request.encode('utf-8'))
        logging.info("HTTP request sent")

        # Receive HTTP response
        response_data = protocol.receive_data()
        logging.info("Received response from server")

        # Process the response
        print("Received HTTP response:")
        print(response_data.decode('utf-8'))

    except Exception as e:
        logging.error(f"Test failed: {e}")
    finally:
        protocol.socket.close()

if __name__ == "__main__":
    run_test()