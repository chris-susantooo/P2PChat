#!/usr/bin/python3

# Student name and No.: Susanto Christopher Alvin 3035371915
# Student name and No.: Chau Wing Yu 3035377660
# Development platform: Windows 10
# Python version: Python3
# Version: 2.0


from tkinter import *
import sys
import socket
import threading
import time
import select

#
# Global variables
#

username = ""
roomname = ""

rsIP = sys.argv[1]
rsPort = int(sys.argv[2])

myIP = ""
myPort = int(sys.argv[3])

myMSID = 0
myHashID = 0
myMsgID = 0

status = "STARTED" # STARTED, NAMED, JOINED, CONNECTED, TERMINATED
ack = False

sockls = socket.socket()
sockls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sockls.bind(('', myPort))
sockls.listen(10)

sockfd = socket.socket()
sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sockfd.bind(('', myPort))

fdlink = None

gList = []
socketList = [sockls]
writeList = {}

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form a string that be the input 
# to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff

#
# This is the function for processing a received byte message
# It splits the message with protocol sentinel ':'
# then returns a list of useful strings
#
def unpack_msg(rmsg):
	rmsg = str(rmsg)[2:-7]
	if rmsg[0] == 'T': #avoid splitting message content by ':'
		return rmsg.split(":", 6)
	else:
		return rmsg.split(":")

#
# This is the function for establishing a TCP connection
# with the specified socket and address, only when
# there is no existing connection to the target
# pflag: set false to avoid printing out errors
#
def tcp_connect(sock, addr, pflag = True):
	global socketList, myIP

	if sock not in socketList: #if no prior connection
		try:
			sock.connect(addr)
			socketList.append(sock)

			if not myIP: #initialize myIP for future use
				myIP = sock.getpeername()[0]

		except socket.error as emsg:
			if pflag:
				print("Error trying to connect to", addr, emsg)
		
#
# This is the function for retrieving the newest
# membership list from the room server
# Returns True if gList is updated, False otherwise
#
def get_gList(first=False):
	global sockfd, myMSID

	tcp_connect(sockfd, (rsIP, rsPort)) #try to establish connection

	try:
		#compose message and send
		msg = "J:" + roomname + ":" + username + ":" + myIP + ":" + str(myPort) + "::\r\n"
		sockfd.send(msg.encode("ascii"))

		rmsg = sockfd.recv(1000)
		head, *body = unpack_msg(rmsg) #unpack rmsg

		if head == 'M': #message contains membership information
			newMSID = int(body.pop(0))
			if myMSID != newMSID: #reconstruct gList if this is newer
				gList.clear()
				myMSID = newMSID

				#loop until all user info are transferred to gList
				while body:
					uname, uIP, uPort, *rest = body
					gList.append((uname, uIP, int(uPort)))
					del body[:3]

				#setup a forward link if it is not present
				if not fdlink and not first:
					fwd_link_thr = threading.Thread(target=SETUPFWDLINK)
					fwd_link_thr.start()
				
				return True

		elif head == 'F': #message indicates room server error
			CmdWin.insert(1.0, "\nError:", body)

	except socket.error as emsg:
		print("Error trying to get gList", emsg)

	return False

#
# This is the function for relaying messages to other connected peers
# It also prints out results in MsgWin and CmdWin
#
def relay_message(sd, origin_uname, originHID, origin_msgID, msg, rmsg):
	global writeList

	MsgWin.insert(1.0, "\n[" + origin_uname + "] " + msg)
	try: #peer with originHID is connected with us, keep socket
		writeList[originHID] = (writeList[originHID][0], origin_msgID)
	except: #peer with originHID is not connected with us, set socket to None
		writeList[originHID] = (None, origin_msgID)

	sent = False
	for p, m in writeList.values(): #send message to all connected peers
		if p and p != sd and p != writeList[originHID][0]: #filter out origin and sender peer
			try:
				p.send(rmsg)
				sent = True
			except socket.error:
				remove_socket(p) #connection error, disconnect from this peer

	if sent:
		CmdWin.insert(1.0, "\nRelay the message to other peer")

#
# This is the function to safely disconnect us from target peer,
# which cleans up socketList and writeList apart from closing the socket
# It also checks if it is the forward link which gets destroyed,
# and set it up again by pinging new gList and calling SETUPFWDLINK()
#
def remove_socket(sock):
	global socketList, writeList, status, fdlink

	if sock in socketList: #remove from socketList
		socketList.remove(sock)

	for key, val in writeList.items(): #remove from writeList
		if val[0] == sock:
			del writeList[key]
			break

	if sock == fdlink: #declare forward link lost if destroyed
		fdlink = None
	
	sock.close()
	#downgrade status if we are not connected anymore
	if not fdlink and not writeList: #if no forward link, no backward link
		status = "JOINED"
	
	get_gList() #retrieve newest membership list

	fwd_link_thr = threading.Thread(target=SETUPFWDLINK)
	fwd_link_thr.start() #chatroom network changed, call SETUPFWDLINK()

#
# This is the function to send a poke message to a connected peer
# It sleeps for 2s after sent to wait for ACK
# Prints out the result of success/failure of the poke
#
def SENDPOKE(name, addr):
	global ack

	pmsg = "K:" + roomname + ":" + username + "::\r\n" #poke message
	try:
		#setup connection and send
		sockpk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sockpk.bind(('', myPort))
		sockpk.sendto(pmsg.encode("ascii"), addr)
		
		CmdWin.insert(1.0, "\nHave sent a poke to " + name)
		time.sleep(2)

		if ack: #check if ACK is received
			CmdWin.insert(1.0, "\nReceived ACK from " + name)
			ack = False
		else:
			CmdWin.insert(1.0, "\nNo ACK received from " + name)

	except socket.timeout as emsg:
		print(str(emsg))

#
# This is the thread function to listen to incoming UDP messages
# It prints out the poke message and sends ACK back to sender
# after receiving a poke message
#
def LISTENPOKE():
	global ack

	#setup connection
	sockpk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sockpk.bind((myIP, myPort))
	sockpk.setblocking(False) #set socket to non-blocking for while-loop to run

	while status != "TERMINATED": #loop until Quit button is pressed
		try:
			rmsg, addr = sockpk.recvfrom(1000) #receive UDP message
			head, rname, uname, *rest = str(rmsg)[2:].split(":") #unpack rmsg
			if head == 'K' and rname == roomname: #UDP message is a poke message
				sockpk.sendto("A::\r\n".encode("ascii"), addr)
				CmdWin.insert(1.0, "\nReceived a poke from " + uname)
				MsgWin.insert(1.0, "\n[" + uname + "] You have been poked! <3")
			elif rmsg == b"A::\r\n": #UDP message is an ACK
				ack = True #signal SENDPOKE()
		except socket.error:
			pass

#
# This is the thread function to maintain current status to room server
# It sends a join request to the room server every 20s
#
def KEEPALIVE():
	while status != "TERMINATED":
		#wait for 20s unless terminated
		for i in range(20):
			time.sleep(1)
			if status == "TERMINATED":
				break
		#send join request to server
		get_gList()

#
# This is the thread function to set up a forward link for the peer
# It appends the new connection socket to socketList and writeList
# It will also be called when chatroom network has changed, i.e. some peer disconnected
#
def SETUPFWDLINK():
	global myHashID, fdlink, socketList, writeList, status
	
	#sort gList according to the hash value of each item in gList
	gList.sort(key=lambda member: sdbm_hash(member[0] + member[1] + str(member[2])))
	myHashID = int(sdbm_hash(username + myIP + str(myPort)))
	start = (gList.index((username, myIP, myPort)) + 1) % len(gList)
	#calculate hash value for gList[start]
	currentHashID = int(sdbm_hash("".join(str(x) for x in gList[start])))

	#main logic for selecting a P2PChat peer
	while currentHashID != myHashID:
		uname, uIP, uPort = gList[start]
		#check if target address is already connected by an existing socket in writeList
		if (uIP, uPort) in [sock.getpeername() for sock, rest in writeList.values() if sock]:
			start = (start + 1) % len(gList)
		else: #no existing connection
			try:
				#set up connection
				fdlink = socket.socket()
				fdlink.connect((uIP, uPort))

				#handshaking procedure
				msg = "P:" + roomname + ":" + username + ":" + myIP + ":" + str(myPort) + ":" + str(myMsgID) + "::\r\n"
				fdlink.send(msg.encode("ascii"))

				#expect to receive handshaking reply, unpack
				rmsg = fdlink.recv(1000)
				head, uMsgID = unpack_msg(rmsg)

				if head == 'S': #successfully established forward link
					socketList.append(fdlink)
					writeList[currentHashID] = (fdlink, int(uMsgID))

					CmdWin.insert(1.0, "\nSuccessfully linked to the group - via " + uname)
					status = "CONNECTED"
					return
				else:
					start = (start + 1) % len(gList)
			except socket.error:
				print("Failure to establish forward link to ", (uIP, uPort))
				start = (start + 1) % len(gList)
		currentHashID = int(sdbm_hash("".join(str(x) for x in gList[start]))) #calculate next

#
# This is the thread function to listen to all TCP messages from P2PChat peers
# It accepts new connections, processes peer handshaking and message forwarding
# It also detects broken connections and calls remove_socket()
#
def LISTENPEER():
	global sockls, socketList, writeList, status

	while status != "TERMINATED": #loop until Quit button is pressed
		try:
			Rready, Wready, Eready = select.select(socketList, [], [], 1) #non-blocking
		except select.error as emsg:
			print("Error selecting sockets from socketList. ", emsg)

		if Rready: #at least a socket is ready for operation
			for sd in Rready:
				if sd == sockls: #new connection request to listening socket
					new, addr = sockls.accept()
					socketList.append(new) #accept and append to socketList for future select
				else:
					try:
						rmsg = sd.recv(1000) #try to receive message
					except:
						rmsg = None

					if rmsg: #no error
						head, *body = unpack_msg(rmsg) #unpack rmsg

						if head == 'P': #handshaking request
							rname, uname, uIP, uPort, uMsgID = body
							#try to update gList first if initiating peer is unknown
							if (uname, uIP, int(uPort)) not in gList:
								get_gList()
							#complete handshaking if peer is now known in new gList
							if (uname, uIP, int(uPort)) in gList:
								msg = "S:" + str(myMsgID) + "::\r\n"
								try:
									sd.send(msg.encode("ascii")) #complete handshaking
									#append hash value of peer along with its msgID
									writeList[int(sdbm_hash(uname + uIP + uPort))] = (sd, int(uMsgID))

									status = "CONNECTED"
									CmdWin.insert(1.0, "\n" + uname + " has linked to me")
								except socket.error:
									remove_socket(sd) #remove socket due to connection error
							else:
								remove_socket(sd) #remove socket due to connection error

						elif head == 'T': #text message forwarding
							origin_rname, originHID, origin_uname, origin_msgID, msgLength, content = body
							if origin_rname == roomname: #proceed if both peers are in same chatroom
								if int(originHID) not in [sdbm_hash(m[0] + m[1] + str(m[2])) for m in gList]:
									get_gList() #try to update gList if peer with originHID is unknown
								
								if int(originHID) in [sdbm_hash(m[0] + m[1] + str(m[2])) for m in gList]:
									if int(originHID) in writeList: #proceed if peer is in gList this time
										if int(origin_msgID) > writeList[int(originHID)][1]: #only process new msgID
											relay_message(sd, origin_uname, int(originHID), int(origin_msgID), content, rmsg)
										else: #msgID conflict, not relaying the message
											CmdWin.insert(1.0, "\nError: message seen before")
									else: #still proceed forwarding message, but origin peer socket is unknown
										relay_message(sd, origin_uname, int(originHID), int(origin_msgID), content, rmsg)
							else:
								CmdWin.insert(1.0, "\nError: message from other chatroom")
					else:
						remove_socket(sd) #remove socket due to connection error
		
#
# Functions to handle user input
#

def do_User():
	global username, status

	if status != "JOINED" and status != "CONNECTED":
		val = userentry.get()
		if val:
			username = val
			CmdWin.insert(1.0, "\n[User] username: " + username)
			status = "NAMED"
		else:
			CmdWin.insert(1.0, "\n[User] rejected: empty username")
	else:
		CmdWin.insert(1.0, "\n[User] rejected: you are in chatroom")
	userentry.delete(0, END)


def do_List():
	global sockfd

	#connect to room server and send list request
	tcp_connect(sockfd, (rsIP, rsPort))
	sockfd.send("L::\r\n".encode("ascii"))

	#handle response message
	rmsg = sockfd.recv(1000)
	head, *body = unpack_msg(rmsg)
	if head == 'G': #message with group names
		if rmsg == b"G::\r\n": #No groups
			CmdWin.insert(1.0, "\nNo active chatrooms")
		else: #have groups
			for chatroom in body: #extract group names
				CmdWin.insert(1.0, "\n	" + chatroom)
			CmdWin.insert(1.0, "\nHere are the active chatrooms:")
	elif head == 'F': #message with error
		CmdWin.insert(1.0, "\nError:", body)


def do_Join():
	global sockfd, roomname, status, gList

	if username or status == "STARTED":
		if status != "JOINED" and status != "CONNECTED":
			instr = userentry.get()
			if instr and not roomname:
				roomname = instr

				if get_gList(True): 

					for member in gList:
						CmdWin.insert(1.0, "\n" + member[0])
					CmdWin.insert(1.0, "\nHere are the list of members:")

					CmdWin.insert(1.0, "\nMy IP address: " + myIP + " My listening port: " + str(myPort))

					listen_poke_thr = threading.Thread(target=LISTENPOKE)
					listen_poke_thr.start()
					
					keep_alive_thr = threading.Thread(target=KEEPALIVE)
					keep_alive_thr.start()

					CmdWin.insert(1.0, "\nKeepalive thread - Start execution")

					listen_peer_thr = threading.Thread(target=LISTENPEER)
					listen_peer_thr.start()

					fwd_link_thr = threading.Thread(target=SETUPFWDLINK)
					fwd_link_thr.start()

					status = "JOINED"
			else:
				CmdWin.insert(1.0, "\nPlease input roomname first before joining")
		else:
			CmdWin.insert(1.0, "\nAlready in chatroom: " + roomname + ". Cannot JOIN again")
	else:
		CmdWin.insert(1.0, "\nPlease input nickname first")
	
	userentry.delete(0, END)


def do_Send():
	global myMsgID, writeList

	msg = userentry.get()
	if msg and status == "CONNECTED":
		MsgWin.insert(1.0, "\n[" + username + "] " + msg)
		myMsgID += 1 #increment for each new message to distinguish from the old ones
		smsg = "T:" + roomname + ":" + str(myHashID) + ":" + username + ":" + str(myMsgID) + ":" + str(len(msg)) + ":" + msg + "::\r\n"
		
		for p, m in writeList.values(): #broadcast to all valid sockets in writeList
			if p: #None objects with msgID exist in writeList due to unknown origin peers
				try:
					p.send(smsg.encode("ascii")) #send out the message
				except socket.error:
					remove_socket(p) #remove socket due to connection error
		userentry.delete(0, END)

def do_Poke():
	if status == "JOINED" or status == "CONNECTED":
		targetname = userentry.get()
		if targetname:
			for uname, uIP, uPort in gList:
				if uname == targetname: #poke target in group, send the poke
					send_poke_thr = threading.Thread(target=SENDPOKE, args=(uname, (uIP, uPort)))
					send_poke_thr.start()
					return
			CmdWin.insert(1.0, "\nError: " + targetname + " not in chatroom")
		else: #targetname is empty, prompt for another round of input
			CmdWin.insert(1.0, "\n" + " ".join([member[0] for member in gList]))
			CmdWin.insert(1.0, "\nTo whom do you want to send the poke?")
	else:
		CmdWin.insert(1.0, "\nError: " + username + " not in chatroom")


def do_Quit():
	global status

	#actively destroy connection with other peers to avoid their freeze
	for p, m in writeList.values():
		if p:
			try:
				p.shutdown(2) #shut down both reading and writing channels
				p.close()
			except:
				pass

	status = "TERMINATED" #signal all running loops to stop
	sys.exit(0)


#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	win.mainloop()

if __name__ == "__main__":
	main()