# P2PChat
An academic project on implementing a P2P and client-server architecture chat program using Python.

## Prerequisites
Python 3 is required for running this project. If not installed, please visit the [download site](https://www.python.org/).

## Usage
We need to first execute the server program, it keeps track on the grouping information,  such as the number of groups, and membership information of each group, etc.
Then we can run the P2PChat client afterwards.  
1. With any bash command line, navigate to the directory where room_server_64 is stored.
2. Change permissions for the file, if neccessary, in order to execute it:
        chmod 777 room_server_64
3. Run the binary executable:
        ./room_server_64 \[<listening_port>]
4. At this point where the server is ready and listening, we can launch our client:
        P2PChat.py <server_ip> <server_port> <my_listening_port>
  
Replace the arguments in brackets with corresponding inputs. By default, the server listens the port 32340, unless the optional argument is given while executing it. Choose any appropriate port number to your liking for     <my_listening_port>, although no other client instances should be sharing the port.