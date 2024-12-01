import socket
import struct
import random
import time
import logging
from collections import namedtuple

Header = namedtuple('Header', ['version', 'type', 'window', 'seq_num', 'ack_num', 'checksum'])

# Packet types
SYN, SYN_ACK, ACK, DATA, FIN = range(5)

class NetworkSimulator:
    def __init__(self, loss_rate=0.1):
        self.loss_rate = loss_rate

    def should_drop(self):
        return random.random() < self.loss_rate

class ReliableProtocol:
    def __init__(self, host, port, simulator=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(1.0)  # 1 second timeout
        self.host = host
        self.port = port
        self.simulator = simulator or NetworkSimulator()

        # Basic state
        self.seq_num = random.randint(0, 2**32 - 1)
        self.expected_seq_num = 0
        self.connected = False

        # Flow and congestion control
        self.cwnd = 1.0      # Congestion window (in segments)
        self.ssthresh = 16.0 # Slow start threshold
        self.rwnd = 65535    # Receiver window (from server)
        self.recv_window_size = 65535  # Client's receive window size

        # Buffers
        self.send_buffer = {}
        self.recv_buffer = {}

        # Logging
        logging.basicConfig(filename='client_protocol.log', level=logging.INFO)

    def create_packet(self, type, seq_num=None, ack_num=None, data=b''):
        if seq_num is None:
            seq_num = self.seq_num
        if ack_num is None:
            ack_num = self.expected_seq_num

        header = Header(
            version=1,
            type=type,
            window=self.recv_window_size,  # Set window to a fixed valid value
            seq_num=seq_num % (2**32),
            ack_num=ack_num % (2**32),
            checksum=0
        )
        header_bytes = struct.pack('!BBHLLH', *header)
        packet = header_bytes + data

        # Zero out checksum field for calculation
        packet_zero_checksum = packet[:12] + b'\x00\x00' + packet[14:]

        # Calculate checksum
        checksum = self.calculate_checksum(packet_zero_checksum)

        # Insert checksum into the packet
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]

        return packet


    def calculate_checksum(self, data):
        """Compute checksum of the given data using one's complement."""
        # Ensure even number of bytes
        if len(data) % 2 != 0:
            data += b'\x00'  # Padding

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            # Carry around addition
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF  # One's complement

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
                    self.rwnd = header.window
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
        """Send data using sliding window and congestion control"""
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
            # Send packets within the congestion window and receiver's window
            while (next_seq - acked_seq) < min(int(self.cwnd * 1400), self.rwnd):
                if (next_seq - base_seq) >= len(data):
                    break
                segment_index = (next_seq - base_seq) // 1400
                segment = segments[segment_index]
                packet = self.create_packet(DATA, seq_num=next_seq, data=segment)
                self.send_with_simulation(packet, (self.host, self.port))
                logging.info(f"Sent DATA with seq_num={next_seq}")
                window[next_seq] = packet
                timers[next_seq] = time.time()
                next_seq += len(segment)

            try:
                data, addr = self.socket.recvfrom(1500)
                header = self.parse_header(data)
                if header.type == ACK:
                    logging.info(f"Received ACK with ack_num={header.ack_num}")
                    ack_num = header.ack_num
                    self.rwnd = header.window
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
                        logging.info(f"Updated cwnd={self.cwnd}")
                    else:
                        # Duplicate ACK
                        logging.warning(f"Received duplicate ACK with ack_num={header.ack_num}")
                elif header.type == FIN:
                    logging.info("Received FIN from server")
                    # Send ACK for FIN
                    fin_ack_pkt = self.create_packet(ACK)
                    self.send_with_simulation(fin_ack_pkt, addr)
                    logging.info("Sent ACK for FIN")
                    break
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
                        self.ssthresh = max(self.cwnd / 2, 1)
                        self.cwnd = 1.0
                        logging.info(f"Timeout occurred. Updated ssthresh={self.ssthresh}, cwnd={self.cwnd}")

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
                    logging.info(f"Received DATA from server with seq_num={header.seq_num}, length={len(data[14:])}")
                    seq_num = header.seq_num
                    if seq_num == self.expected_seq_num:
                        # Correct packet received
                        data_payload = data[14:]  # Extract data after header
                        received_data += data_payload
                        self.expected_seq_num += len(data_payload)
                        # Send ACK
                        ack_pkt = self.create_packet(ACK)
                        self.send_with_simulation(ack_pkt, addr)
                        logging.info(f"Sent ACK with ack_num={self.expected_seq_num}")
                    elif seq_num > self.expected_seq_num:
                        # Future packet, buffer it
                        self.recv_buffer[seq_num] = data[14:]
                        # Send duplicate ACK
                        ack_pkt = self.create_packet(ACK)
                        self.send_with_simulation(ack_pkt, addr)
                        logging.info(f"Buffered out-of-order packet, sent ACK with ack_num={self.expected_seq_num}")
                    else:
                        # Duplicate packet, send ACK again
                        ack_pkt = self.create_packet(ACK)
                        self.send_with_simulation(ack_pkt, addr)
                        logging.info(f"Received duplicate DATA, sent ACK with ack_num={self.expected_seq_num}")
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
        calculated_checksum = self.calculate_checksum(packet_zero_checksum)
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
        print(response_data.decode('utf-8', errors='replace'))

    except Exception as e:
        logging.error(f"Test failed: {e}")
    finally:
        protocol.socket.close()

if __name__ == "__main__":
    run_test()
