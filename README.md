
# Pipelined Reliable Transfer Protocol

## Introduction
This project implements a custom **Pipelined Reliable Transfer Protocol** inspired by TCP. The protocol is designed to operate over UDP sockets, providing features such as:

- Connection establishment and termination
- Reliable data transfer
- Flow control
- Congestion control
- Error handling

The robustness of the protocol was tested in controlled environments by simulating packet loss and errors. Traffic between the client and server was analyzed using Wireshark, showcasing the connection-oriented nature of the protocol and the implementation of flow control and congestion control mechanisms.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Documentation](#documentation)
- [Contributors](#contributors)
- [License](#license)

## Features
- **Custom Protocol over UDP**: Simulates TCP-like functionality using UDP sockets.
- **Reliable Data Transfer**: Ensures the integrity and correctness of data transmission.
- **Flow and Congestion Control**: Implements mechanisms to optimize performance under varying network conditions.
- **Error Simulation**: Tests robustness by introducing packet loss and errors.
- **Wireshark Analysis**: Verifies performance and correctness of the protocol.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/repo-name.git
   cd repo-name
   ```
2. Ensure Python 3 is installed on your system.

3. Install any required dependencies (see [Dependencies](#dependencies)).

## Usage
### Starting the Server
Run the server script to start listening for incoming connections:
```bash
python server.py
```

### Running the Client
Initiate the client script to connect to the server and start data transfer:
```bash
python client.py
```

## Testing
The protocol has been rigorously tested with simulated scenarios including:
- Packet loss
- Corrupted packets
- High network latency

### Wireshark Analysis
Traffic between the client and server was captured and analyzed using Wireshark. The analysis demonstrates:
- Connection-oriented communication
- Effective flow control and congestion control mechanisms
- Reliable data transfer under adverse conditions

## Dependencies
- Python 3.x
- Wireshark (for network traffic analysis)

## Documentation
### Code Structure
- `client.py`: Implements the client-side logic for initiating connections, sending data, and handling acknowledgments.
- `server.py`: Implements the server-side logic for accepting connections, receiving data, and sending acknowledgments.
- `test.html`: Example HTML file used in testing data transfer.

### Example HTML Transfer
The `test.html` file serves as a sample for testing the protocol. It contains basic HTML content to verify data integrity during transfer.

## Contributors
- **Your Name** - Protocol Design and Implementation
- **Additional Contributors** - Testing and Analysis

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
