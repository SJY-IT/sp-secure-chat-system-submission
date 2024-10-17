"""
The University of Adelaide - Semester 2, 2024
Secure Programming Advanced Course Assignment - Secure Chat System
Group Name: Group 1
Authors: Bishal Adhikari, Den Tit Vityia Meas, Se Jin Yoon, Victor Li 
"""
def parse_chat_command(parts):
    if len(parts) >= 5 and parts[1] == '-u' and parts[3] == '-m':
        user = parts[2]
        message = ' '.join(parts[4:])[1:-1]  # Remove the surrounding quotes
        return 1, '/chat', [user], message
    return 0, '', [], ''

def parse_groupchat_command(parts):
    if len(parts) >= 6 and parts[1] == '-u' and '-m' in parts:
        m_index = parts.index('-m')
        users = parts[2:m_index]
        message = ' '.join(parts[m_index + 1:])[1:-1]  # Remove the surrounding quotes
        return 1, '/groupchat', users, message
    return 0, '', [], ''

def parse_publicchat_command(parts):
    if len(parts) >= 2:
        message = ' '.join(parts[1:])[1:-1]  # Remove the surrounding quotes
        return 1, '/publicchat', [], message
    return 0, '', [], ''

def parse_command(command):
    parts = command.split(' ')
    if parts[0] == '/exit':
        return 1, '/exit', [], ''
    elif parts[0] == '/client_list_request':
        return 1, '/client_list_request', [], ''
    elif parts[0] == '/chat':
        return parse_chat_command(parts)
    elif parts[0] == '/groupchat':
        return parse_groupchat_command(parts)
    elif parts[0] == '/publicchat':
        return parse_publicchat_command(parts)
    else:
        return 0, '', [], ''

def handle_command(command):
    isvalid, cmd_used, users, message = parse_command(command)
    if isvalid:
        if cmd_used == '/chat':
            print(f"Chat message from {users[0]}: {message}")
        elif cmd_used == '/groupchat':
            print(f"Group chat message from {', '.join(users)}: {message}")
        elif cmd_used == '/publicchat':
            print(f"Public chat message: {message}")
        elif cmd_used == '/exit':
            print("Client shutting down.")
        elif cmd_used == '/client_list_request':
            print("Client list requested.")
    else:
        print("Invalid command")
