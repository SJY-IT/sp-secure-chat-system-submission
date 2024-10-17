"""
The University of Adelaide - Semester 2, 2024
Secure Programming Advanced Course Assignment - Secure Chat System
Group Name: Group 1
Authors: Bishal Adhikari, Den Tit Vityia Meas, Se Jin Yoon, Victor Li 
"""

import asyncio
import websockets
import sys
import crypt_util
import json
from command_parser import parse_command
# only for generating random usernames on clientside
import random

client_state = {
    'counter': 0,
    'private_key': None,
    'public_key': None,
}

# Dictionary to store client public keys with randomly generated 8-digit usernames
client_keys = {}

async def start_client(server_address):
    client_state['private_key'], client_state['public_key'] = crypt_util.generate_rsa_keypair()

    """Connect to the WebSocket server and handle communications."""
    uri = f"ws://{server_address[0]}:{server_address[1]}"
    print(f"Connecting to {uri}")


    try:
        async with websockets.connect(uri, ping_timeout=None) as websocket:
            await send_hello_message(websocket)

            print(f"Connected to server at {uri}")

            while True:
                # 2. Wait for user input
                command = input("Enter command: ")

                # Parse and handle the command
                isvalid, cmd_used, users, message = parse_command(command)
                
                if isvalid:
                    if cmd_used == '/exit':
                        print("Client shutting down.")
                        await websocket.close()
                        break
                    elif cmd_used == '/client_list_request':
                        await send_client_list_request(websocket)
                    elif cmd_used == '/chat':
                        # Send a private chat message to a specific user
                        await send_chat_message(websocket, [users[0]], message)
                    elif cmd_used == '/groupchat':
                        # Send a group chat message
                        await send_chat_message(websocket, users, message)
                    elif cmd_used == '/publicchat':
                        # Send a public chat message
                        await send_public_chat_message(websocket, "public_user", message)  # You can update "public_user" with the actual user's fingerprint
                    elif cmd_used == '/comment':
                        print(f"Comment from {users[0]}: {message}")
                else:
                    print("Invalid command")

                # 3. Process incoming messages from the server
                try:
                    message = await websocket.recv()
                    server_response = json.loads(message)

                    # Verify if it's a signed message (type: "signed_data")
                    if server_response["type"] == "signed_data":
                        data = server_response["data"]
                        counter = server_response["counter"]
                        signature = server_response["signature"]


                        # Verify the signature 
                        if crypt_util.is_signature_valid(json.dumps(server_response), signature, client_state.public_key):
                            # Process "client_list" or "chat" based on data type
                            if data["type"] == "client_list":
                                handle_client_list(data)
                            elif data["type"] == "chat":
                                decrypted_message = handle_incoming_chat(data)
                                print("Decrypted Chat Message:", decrypted_message)
                            elif data["type"] == "public_chat":

                        else:
                            print("Invalid signature, message discarded.")
                except Exception as e:
                    print(f"Error receiving message from server: {e}")

                    while True:
                        message = input("Enter message to send (type '/exit' to quit): ")
                        if message.lower() == '/exit':
                            print("Client shutting down.")
                            break

                        await websocket.send(message)
                        response = await websocket.recv()
                        print(f"Received from server: {response}")

            

    except websockets.ConnectionClosed:
        print("Connection closed by the server.")

    except KeyboardInterrupt:
        print("Client shutting down.")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    server_address = (sys.argv[1], sys.argv[2])
    asyncio.run(start_client(server_address))

if __name__ == "__main__":
    main()

async def send_hello_message(websocket):
    # Prepare the 'hello' message, send client's public key
    hello_data = {
        "type": "hello",
        "public_key": crypt_util.export_public_key(client_state['public_key'])
    }
    signed_message = sign_message(hello_data)
    await websocket.send(signed_message)

async def send_chat_message(websocket, destination_servers, encrypted_message, encrypted_keys, iv):
    # Prepare the 'chat' message with encrypted AES ciphertext
    chat_data = {
        "type": "chat",
        "destination_servers": destination_servers,
        "iv": iv,
        "symm_keys": encrypted_keys,
        "chat": encrypted_message
    }
    signed_message = sign_message(chat_data)
    await websocket.send(signed_message)

async def send_public_chat_message(websocket, sender_fingerprint, message):
    # Prepare the public chat message
    public_chat_data = {
        "type": "public_chat",
        "sender": sender_fingerprint,
        "message": message
    }
    signed_message = sign_message(public_chat_data)
    await websocket.send(signed_message)

async def send_client_list_request(websocket):
    # Prepare client list request
    client_list_request = {
        "type": "client_list_request"
    }
    await websocket.send(json.dumps(client_list_request))  # No signing needed for client list request

def sign_message(data):
    # Increment the counter for each message to avoid replay attacks
    client_state['counter'] += 1
    counter_value = client_state['counter']

    # Prepare message structure
    message = {
        "type": "signed_data",
        "data": data,
        "counter": counter_value
    }

    # Create the message signature
    message_string = json.dumps(data) + str(counter_value)
    signature = crypt_util.get_signature(message_string, client_state['private_key'])
    message['signature'] = signature

    return json.dumps(message)

def generate_random_username():
    """Generate a random 8-digit username."""
    return str(random.randint(10000000, 99999999))

def handle_client_list(data):
    # Process the server's client list response from the "data" field
    for server in data["servers"]:
        address = server["address"]
        clients = server["clients"]
        print(f"Server Address: {address}")
        
        for client_key in clients:
            # Generate a random 8-digit username for each client
            username = generate_random_username()

            # Ensure the username is unique (in case of collisions)
            while username in client_keys:
                username = generate_random_username()

            # Store the client's public key with the generated username
            client_keys[username] = client_key
            print(f"Stored client with username {username} and public key: {client_key}")

def handle_incoming_chat(data):
    # Extract necessary fields from the "data" object
    iv = b64decode(data["iv"])
    encrypted_aes_keys = [b64decode(key) for key in data["symm_keys"]]
    encrypted_chat = b64decode(data["chat"])
    
    # Decrypt the AES key using RSA (assuming rsa_decrypt is defined in crypt_util)
    decrypted_aes_key = rsa_decrypt(encrypted_aes_keys[0])  # Decrypting for the first recipient

    # Use the AES key and IV to decrypt the chat message
    cipher = AES.new(decrypted_aes_key, AES.MODE_GCM, iv)
    decrypted_message = cipher.decrypt(encrypted_chat)

    return decrypted_message.decode("utf-8")

