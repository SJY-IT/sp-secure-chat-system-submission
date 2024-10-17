"""
The University of Adelaide - Semester 2, 2024
Secure Programming Advanced Course Assignment - Secure Chat System
Group Name: Group 1
Authors: Bishal Adhikari, Den Tit Vityia Meas, Se Jin Yoon, Victor Li 
"""

*Note: There may be vulnerable codes. Use at own risk.

For Client
**client-app.py**
- Client code, basic structure of a client.
- Takes command-line arguments (host, port) for use to connect to a server.
- When connected, messages can be sent to the server
- When message is received, simply prints out to the terminal
- Usage: `python3 client-app.py 127.0.0.1 9000`

**Commands**

_Chat_
One-on-one chat
 - '/chat -u user -m "message here"',
 Group chat
 - '/groupchat -u user1 user2 user3 -m "message here"',
 Public chat
 - '/publicchat "message here"',

 Client list request
 - '/client_list_request',

 Quit Client
 - '/exit'


For Server
How to run:
    - Configure the address and port number you want to run the server on in the my_server.json file
    - Configure the addresses and port numbers of the servers in the neighbourhood that you want to attempt connect to in the predefined_servers.json
    - makesure uptodate packages are installed: pycryptodome, json, jsonschema, websockets, asyncio
    - Run with: python3 server-app.py

Note that the implementation is not complete yet. Still in progress, so may not run as intended.

Brief description of the server-app.py:

The WebSocket server is designed to manage connections from both clients and other servers. 
It facilitates communication through a structured message format, allowing clients to send and receive data, and enabling servers to relay information to connected clients. The server maintains a record of connected clients and servers, handles client requests, and manages the integrity of communications through signature verification.

Key Components

Configuration
- Server Configuration: The server configuration is loaded from a JSON file (my_server.json), which contains the server's address and port.
Predefined Servers: A list of predefined servers is loaded from predefined_servers.json, which contains the addresses and public keys of other servers for connection purposes.

Connection Management
- Connected Clients and Servers: The server maintains lists to track directly connected clients and servers. It also tracks reachable clients in the neighborhood.
- WebSocket Connections: Sets are used to manage active WebSocket connections for both clients and servers, allowing for efficient connection tracking and message relay.

Message Handling
- Initial Connection Handling: When a new connection is established, the server reads the first message to determine if the connection is from a client or a server. It validates the message format and checks the message type (hello or server_hello).
- Signature Verification: For both client and server connections, the server verifies signatures to ensure the integrity and authenticity of the messages being exchanged. This is crucial for maintaining a secure communication channel.

Client and Server Interaction
- Client Connection Handling: If the initial message is a client's hello message, the server adds the client to its lists and starts listening for further messages. It can process various message types, including:
- Client List Requests: Clients can request a list of reachable clients, which is sent as a response.
- Chat Messages: Messages designated for chat (either private or public) are relayed to all connected clients and servers.
- Server Connection Handling: If the initial message is a server's hello message, the server verifies the sender's address and public key, adding the server to its list. It can also relay messages received from other servers to its connected clients.

Disconnection Handling
- Graceful Disconnection: The server handles disconnections by removing clients or servers from its lists and sending updates to all connected entities. This ensures that the state remains consistent across the network.
Connection to Other Servers
- Automatic Connection Attempts: The server attempts to connect to predefined servers upon startup. If a connection fails, it retries up to a specified number of times before giving up.

