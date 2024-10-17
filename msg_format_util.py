"""
The University of Adelaide - Semester 2, 2024
Secure Programming Advanced Course Assignment - Secure Chat System
Group Name: Group 1
Authors: Bishal Adhikari, Den Tit Vityia Meas, Se Jin Yoon, Victor Li 
"""

import json
from jsonschema import validate, ValidationError
import logging

# Configure logging
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define JSON schemas for each message type
schemas = {
    "client_hello": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["signed_data"]},
            "data": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["hello"]},
                    "public_key": {"type": "string"}
                },
                "required": ["type", "public_key"],
                "additionalProperties": False  
            },
            "counter": {"type": "integer"},
            "signature": {"type": "string"}
        },
        "required": ["type", "data", "counter", "signature"],
        "additionalProperties": False  
    },
    "client_list_request": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["client_list_request"]}
        },
        "required": ["type"],
        "additionalProperties": False  
    },
    "server_hello": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["signed_data"]},
            "data": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["server_hello"]},
                    "sender": {"type": "string"}
                },
                "required": ["type", "sender"],
                "additionalProperties": False  
            },
            "counter": {"type": "integer"},
            "signature": {"type": "string"}
        },
        "required": ["type", "data", "counter", "signature"],
        "additionalProperties": False  
    },
    "client_update_request": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["client_update_request"]}
        },
        "required": ["type"],
        "additionalProperties": False  
    },
    "client_update": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["client_update"]},
            "clients": {
                "type": "array",
                "items": {"type": "string"}
            }
        },
        "required": ["type", "clients"],
        "additionalProperties": False  
    },
    "chat": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["signed_data"]},
            "data": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["chat"]},
                    "destination_servers": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "iv": {"type": "string"},
                    "symm_keys": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "chat": {
                        "type": "object",
                        "properties": {
                            "participants": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "message": {"type": "string"}
                        },
                        "required": ["participants", "message"],
                        "additionalProperties": False  
                    }
                },
                "required": ["type", "destination_servers", "iv", "symm_keys", "chat"],
                "additionalProperties": False  
            },
            "counter": {"type": "integer"},
            "signature": {"type": "string"}
        },
        "required": ["type", "data", "counter", "signature"],
        "additionalProperties": False  
    },
    "public_chat": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["signed_data"]},
            "data": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["public_chat"]},
                    "sender": {"type": "string"},
                    "message": {"type": "string"}
                },
                "required": ["type", "sender", "message"],
                "additionalProperties": False  
            },
            "counter": {"type": "integer"},
            "signature": {"type": "string"}
        },
        "required": ["type", "data", "counter", "signature"],
        "additionalProperties": False  
    }
}

def is_message_valid(message_str: str) -> tuple[bool, str]:
    """
    Validate a JSON message string against defined schemas.

    Args:
        message_str (str): The JSON string to validate.

    Returns:
        tuple: A tuple where the first element is a boolean indicating validity,
               and the second is a string providing message type.
    """

    try:
        # Parse the JSON string into a Python dictionary
        message = json.loads(message_str)
    except json.JSONDecodeError:
        return False, "Invalid JSON format"

    
    # Determine the message type
    msg_type = message.get("type")


    # Select the appropriate schema based on the message type
    if msg_type == "signed_data":
        data_type = message["data"].get("type")
        if data_type == "hello":
            schema = schemas["client_hello"]
        elif data_type == "server_hello":
            schema = schemas["server_hello"]
        elif data_type == "chat":
            schema = schemas["chat"]
        elif data_type == "public_chat":
            schema = schemas["public_chat"]
        else:
            # Log and return invalid format
            logging.debug("Parsed message:\n%s", json.dumps(message, indent=4))
            return False, "invalid_format"
    elif msg_type == "client_list_request":
        schema = schemas["client_list_request"]
    elif msg_type == "client_update_request":
        schema = schemas["client_update_request"]
    elif msg_type == "client_update":
        schema = schemas["client_update"]
    else:
        # Log and return invalid format
        logging.debug("Parsed message:\n%s", json.dumps(message, indent=4))
        return False, "invalid_format"

    # Validate the message against the determined schema
    try:
        validate(instance=message, schema=schema)
    except ValidationError as e:
        # Log validation error details
        logging.debug("Parsed message:\n%s", json.dumps(message, indent=4))
        logging.error("Message validation error: %s", e.message)
        return False, "invalid_format"
    
    # Log and return successful validation result
    if (msg_type == "signed_data"):
        logging.info("Message format is valid: %s", message_str)
        return True, data_type
    else:
        logging.info("Message format is valid: %s", message_str)
        return True, msg_type


# Below is a testing script, unwrap from docstring and just run by 'python msg_util.py':

"""
if __name__ == "__main__":
    # Received from Clients Only
    # 1) Client's Hello Message:
    test_message = '''
    {
        "type": "signed_data",
        "data": {
            "type": "hello",
            "public_key": "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ...\\n-----END PUBLIC KEY-----"
        },
        "counter": 1,
        "signature": "base64signatureexample"
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")

    # 2) Client Requesting for Other Clients in the Neighborhood::
    test_message = '''
    {
        "type": "client_list_request"
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")


    # Received from Servers Only
    # 3) Server's Hello Message:
    test_message = '''
    {
        "type": "signed_data",
        "data": {
            "type": "server_hello",
            "sender": "server_123"
        },
        "counter": 2,
        "signature": "serversignatureexample"
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")

    # 4) Request Message for an Updated List of Clients from Another Server:
    test_message = '''
    {
        "type": "client_update_request"
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")

    # 5) Response Message for Client Update Request from Another Server:
    test_message = '''
    {
        "type": "client_update",
        "clients": [
            "client_1",
            "client_2",
            "client_3"
        ]
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")


    # From Clients or Relayed from Other Servers
    # 6) Private Chat Message:
    test_message = '''
    {
        "type": "signed_data",
        "data": {
            "type": "chat",
            "destination_servers": [
                "<Address of recipient's destination server>"
            ],
            "iv": "randominitializationvector",
            "symm_keys": [
                "symmetrickeyexample"
            ],
            "chat": {
                "participants": [
                    "<Fingerprint of sender comes first>"
                ],
                "message": "<Plaintext message>"
            }
        },
        "counter": 3,
        "signature": "chatsignatureexample"
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")

    # 7) Group Chat Message:
    test_message = '''
    {
        "type": "signed_data",
        "data": {
            "type": "chat",
            "destination_servers": [
                "server_x",
                "server_y"
            ],
            "iv": "anotherrandomiv",
            "symm_keys": [
                "groupkeyexample"
            ],
            "chat": {
                "participants": [
                    "user_1",
                    "user_2"
                ],
                "message": "Hey everyone, join the discussion!"
            }
        },
        "counter": 4,
        "signature": "groupchatsignature"
    }
    '''
    
    print(f"Returned: {is_message_valid(test_message)}")

    # 8) Public Chat Message:
    test_message = '''
    {
        "type": "signed_data",
        "data": {
            "type": "public_chat",
            "sender": "user_3",
            "message": "This is a public message!"
        },
        "counter": 5,
        "signature": "publicchatsignature"
    }
    '''
    print(f"Returned: {is_message_valid(test_message)}")
"""
