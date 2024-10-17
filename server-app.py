"""
The University of Adelaide - Semester 2, 2024
Secure Programming Advanced Course Assignment - Secure Chat System
Group Name: Group 1
Authors: Bishal Adhikari, Den Tit Vityia Meas, Se Jin Yoon, Victor Li 
"""

import asyncio
import websockets
import json
import msg_format_util
import crypt_util

# Load server configuration and predefined servers from JSON files
with open('my_server.json', 'r') as file:
    my_server = json.load(file)

with open('predefined_servers.json', 'r') as file:
    predefined_servers = json.load(file)

# Lists to manage connected clients and servers
connected_servers = []
connected_clients = []
reachable_clients = []

# Track websocket connections
server_connections = set()
client_connections = set()

# Add a connected client to the list
def add_connected_client(websocket, public_key, homeserver_address):
    client_info = {
        "address": websocket.remote_address[0],
        "public_key": public_key,
        "homeserver_address": homeserver_address
    }
    connected_clients.append(client_info)
    client_connections.add(websocket)

# Remove a connected client from the list
def remove_connected_client(websocket):
    global connected_clients
    connected_clients = [client for client in connected_clients if client['address'] != websocket.remote_address[0]]
    client_connections.remove(websocket)

# Add a reachable client to the list
def add_reachable_client(websocket, public_key, homeserver_address):
    client_info = {
        "address": websocket.remote_address[0],
        "public_key": public_key,
        "homeserver_address": homeserver_address
    }
    if not any(client['address'] == websocket.remote_address[0] for client in reachable_clients):
        reachable_clients.append(client_info)

# Remove a reachable client from the list
def remove_reachable_client(websocket):
    global reachable_clients
    reachable_clients = [client for client in reachable_clients if client['address'] != websocket.remote_address[0]]

# Add a connected server to the list
def add_connected_server(websocket, public_key):
    server_info = {
        "address": websocket.remote_address[0],
        "public_key": public_key
    }
    connected_servers.append(server_info)
    server_connections.add(websocket)

# Remove a connected server from the list
def remove_connected_server(websocket):
    global connected_servers
    connected_servers = [server for server in connected_servers if server['address'] != websocket.remote_address[0]]
    server_connections.remove(websocket)

# Build a client list message for sending
def get_client_list():
    clients = reachable_clients
    client_list = {
        "type": "client_list",
        "servers": []
    }
    for server in connected_servers:
        server_info = {
            "address": server["address"],
            "clients": []
        }
        for client in clients[:]:
            if client["homeserver_address"] == server["address"]:
                client_info = crypt_util.export_public_key(client["public_key"]).decode('utf-8')
                server_info["clients"].append(client_info)
                clients.remove(client)
        client_list["servers"].append(server_info)
    return client_list

# Handle incoming connections and pass to appropriate handlers
async def handle_initial_connection(websocket, path):
    print(f"Start handling: {websocket.remote_address}")
    try:
        # Step 1: Read the first message from the websocket
        message = await websocket.recv()

        # Step 2: Validate the message format
        is_valid, msg_type = msg_format_util.is_message_valid(message)

        if is_valid:
            message_data = json.loads(message)  # Parse the message
            # Step 3: Check message type
            if msg_type == "hello":
                public_key = message_data["data"]["public_key"]
                public_key = crypt_util.import_key(public_key.encode('utf-8'))
                counter = message_data["counter"]
                signature = message_data["signature"]

                # Prepare the message for signature verification
                combined_message = json.dumps(message_data["data"]) + str(counter)

                # Verify the signature
                if crypt_util.is_signature_valid(combined_message, signature, public_key):
                    # Add the client to connected and reachable lists
                    homeserver_address = my_server["address"]
                    add_connected_client(websocket, public_key, homeserver_address)
                    add_reachable_client(websocket, public_key, homeserver_address)
                    await handle_client_connection(websocket)  # Handle client messages
                else:
                    print("Connection discarded due to invalid signature.")
                    await websocket.close()
            elif msg_type == "server_hello":
                sender_ip = message_data["data"]["sender"]
                signature = message_data["signature"]

                # Validate IP address
                if websocket.remote_address[0] != sender_ip:
                    print("Connection discarded due to IP address mismatch.")
                    await websocket.close()
                    return

                # Check if the IP address is in predefined servers
                server_info = next((server for server in predefined_servers["servers"] if server["address"] == sender_ip), None)
                if server_info is None:
                    print("Connection discarded. IP address not found in predefined_servers.")
                    await websocket.close()
                    return

                # Retrieve the public key for signature verification
                public_key = server_info["public_key"]
                combined_message = json.dumps(message_data["data"]) + str(message_data["counter"])

                # Verify the signature
                if crypt_util.is_signature_valid(combined_message, signature, public_key):
                    add_connected_server(websocket, public_key)
                    await handle_server_connection(websocket)  # Handle server messages
                else:
                    print("Connection discarded due to invalid signature.")
                    await websocket.close()
            else:
                print("Connection discarded due to unexpected message type.")
                await websocket.close()
        else:
            print("Connection discarded due to invalid format.")
            await websocket.close()

    except websockets.exceptions.ConnectionClosed:
        print("Connection closed unexpectedly.")
    except Exception as e:
        print(f"Error handling client: {e}")
        await websocket.close()

async def handle_client_connection(websocket):
    """Handles messages from connected clients."""
    async for message in websocket:
        print(f"Received from client({websocket.remote_address}):\n{message}")

        # Validate the message format
        is_valid, msg_type = msg_format_util.is_message_valid(message)
        
        if not is_valid:
            print("Invalid message format. Discarding message.")
            await handle_disconnection(websocket)
            return

        if msg_type == "client_list_request":
            await send_client_list(websocket)  # Respond with client list
        elif msg_type in ["chat", "public_chat"]:
            await relay_to_clients(message)  # Relay chat messages
            await relay_to_servers(message)
        else:
            print("Invalid message type. Discarding message.")
            await handle_disconnection(websocket)
            return

    await handle_disconnection(websocket)  # Handle disconnection

async def send_client_list(websocket):
    """Sends the list of reachable clients to the requesting websocket."""
    client_list_message = get_client_list()
    await websocket.send(json.dumps(client_list_message))

async def handle_disconnection(websocket):
    """Handles client disconnections and updates connected lists."""
    remove_connected_client(websocket)
    remove_reachable_client(websocket)
    await send_client_update()  # Notify servers of client updates

async def send_client_update():
    """Sends an update of connected clients to all servers."""
    client_update_message = {
        "type": "client_update",
        "clients": [
            crypt_util.export_public_key(client["public_key"]).decode('utf-8')
            for client in connected_clients
        ]
    }
    await relay_to_servers(json.dumps(client_update_message))

async def relay_to_servers(message):
    """Relays messages to all connected servers."""
    for websocket in server_connections:
        await websocket.send(message)

async def relay_to_clients(message):
    """Relays messages to all connected clients except the sender."""
    for websocket in client_connections:
        await websocket.send(message)

async def handle_server_connection(websocket):
    """Handles messages from connected servers."""
    async for message in websocket:
        print(f"Received from neighbour({websocket.remote_address}): {message}")
        await relay_to_clients(message)  # Relay messages to clients

async def connect_to_other_server(uri, max_retries=3):
    """Attempts to connect to another server with retries."""
    retries = 0
    while retries < max_retries:
        try:
            async with websockets.connect(uri) as websocket:
                print(f"Connected to another server at {uri}.")
                await websocket.send("server_hello")
                while True:
                    response = await websocket.recv()
                    print(f"Received from other server: {response}")
        except (websockets.exceptions.InvalidStatusCode, 
                websockets.exceptions.ConnectionClosedError, 
                ConnectionRefusedError) as e:
            retries += 1
            print(f"Could not connect to {uri}: {e}. Retrying in 5 seconds... (Attempt {retries}/{max_retries})")
            await asyncio.sleep(5)  # Wait before retrying

    print(f"Max retries reached. Giving up on connecting to {uri}.")

async def connect_to_all_servers():
    """Attempts to connect to all predefined servers concurrently."""
    tasks = []
    for server in predefined_servers["servers"]:
        uri = f"ws://{server['address']}:{server['port']}"
        tasks.append(asyncio.create_task(connect_to_other_server(uri)))
    await asyncio.gather(*tasks)

async def main():
    """Main entry point for starting the WebSocket server."""
    host = my_server["address"]  # My server IP address
    port = my_server["port"]  # My server port
    server_uri = f"ws://{host}:{port}"  # This server's URI

    # Start the WebSocket server
    server = websockets.serve(handle_initial_connection, host, port)

    async with server:
        print(f"WebSocket server started, listening on {server_uri}")
        await connect_to_all_servers()  # Connect to other servers
        await asyncio.Future()  # Run indefinitely

# Entry point to run main
if __name__ == '__main__':
    asyncio.run(main())
