#!/usr/bin/python

# Import the required packages to create sockets and packing the packets

import socket, sys, fcntl, struct,random,time,os,re,subprocess
from struct import *
import binascii

# Importing package to parse the URL
from urlparse import urlparse
try:
	url = sys.argv[1] # Taking the URL dynamically from the run time and passing it to parsing 
except IndexError:
	print("Invalid number of arguements passed")
	sys.exit()
	
if url=="":
	print("URL is not provided")
	sys.exit()
retrive_urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url)
if retrive_urls==[]:
	print("The format of the given URL is invalid")

if url.count('/')==2: # Checking if the code ends with a "/", if not appending it.
	url = url+'/'
else:
	s = url.split("/")
	d = s[-1]
	if '.' not in d and url.endswith("/")==False:
		url = url+'/'
	else: 
		url = url
def urlparser(URL): # Parsing the URL and extracting the path and related values
	parsedurl=urlparse(URL)
	URL = parsedurl.netloc
	extension=parsedurl.path
	try:	
		dest_ip=socket.gethostbyname(parsedurl.netloc)
	except socket.gaierror:
		print("URL doesn't exist")
		sys.exit()
	split=re.split("/",extension)

	if extension == '/' or url.endswith("/") : # Naming the file, if its a home directory, naming it as index.html. 
		file = 'index.html'			
	else:	
		file = split[-1]
	return file,extension,URL,dest_ip  
file,extension,URL,destinationip = urlparser(url) # Extracting the values from the function

# Extracting the source IP of the machine, considering "eth0" as the Interface

ifname='eth0'
Proc_IP= subprocess.check_output('ifconfig')
v=Proc_IP.find(ifname)
sp=Proc_IP.find("\n\n")
loc=Proc_IP[Proc_IP.find("eth0"):Proc_IP.find("\n\n")].find("inet addr")
Sourceip= Proc_IP[loc+10:Proc_IP.find(" ",loc+10)]

# Function to calculate the checksum of the packet

def checksum(msg):
	c_sum = 0
	c_carry = 0
	Mlen = len (msg)
	Mcons = 2
	while Mlen >= Mcons: # Handling the even or odd length of the request, if the length is odd the last value id passed in the function through if condition below.
		w = ord(msg[c_carry]) + (ord(msg[c_carry+1]) << 8 )
		c_sum = c_sum + w
		c_carry = c_carry + Mcons
		Mlen = Mlen - Mcons # the length of the packet is taken into one variable, considering 2 values at a time a passing them to sum. and deccreamenting the Mlen(length of massage) by Mcons(considered Message vales) in every iteration
		if Mlen == 1:
			c_sum = c_sum + ord(msg[c_carry])

	c_sum = (c_sum>>16) + (c_sum & 0xffff);
	c_sum = c_sum + (c_sum >> 16)
	c_sum = ~c_sum & 0xffff
	return c_sum
 
#create a raw socket. If there is an error, the error code is been displayed
try:
	send_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW) # Raw Socket to send data
	fcntl.fcntl(send_s, fcntl.F_SETFL, os.O_NONBLOCK)
	send_s.bind(("eth0",0))
except socket.error , msg:
	print 'Error in socket creation' + str(msg[0]) + msg[1]
	sys.exit()

recv_s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) # Raw Socket to recieve data
cwd = os.getcwd() # Extracting the current directory
f  = open(cwd+"/"+file, "w") # Creating a file with the above defined filename
# Declaring the global variables used in IP header packing
packet = '';
source_address = socket.inet_aton( Sourceip )
dest_address = socket.inet_aton(destinationip)
placeholder = 0
protocol = socket.IPPROTO_TCP

# Creating an ARP packet

def arp_pack():
	gateway_ip=subprocess.check_output(['route', '-n']).split()[13] # Extracting the default gateway from the "Route -n" output
	destination_ip = socket.inet_aton (gateway_ip) 
	broadcast_mac = struct.pack('!6B', 255, 255, 255, 255, 255, 255)
	source_ip = socket.inet_aton( Sourceip )
	arp_pkt = struct.pack('!HHBBH6s4s6s4s', 1, 2048, 6, 4, 1, source_mac, source_ip, broadcast_mac, destination_ip) # packing the Arp packet
	return arp_pkt

# Defining the unpacking of Arp packet

def arp_unpack(packet):
	global mac
	packet=packet[0]
	split=packet[14:42]
	split = struct.unpack('!HHBBH6s4s6s4s', split)	
	mac = split[5]
	return mac

# Creating Ethernet header using the Mac addresses obtained above

def ether_pack(dest_mac=0,ethype=2048):
	ethernet_packet = struct.pack('!6s6sH', dest_mac, source_mac, ethype)
	return ethernet_packet

# Defing a function to obtain the MAC address of Default gateway

def default_gateway_mac():
	global source_mac
	Source_ip = socket.inet_aton ( Sourceip )
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	sr = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0806))
	s.bind(("eth0",0)) # Binding the socket to "eth0"
	source_mac = s.getsockname()[4] 
	broadcast_mac = struct.pack('!6B', 255, 255, 255, 255, 255, 255)
	ethernet_packet=ether_pack(dest_mac=broadcast_mac,ethype=2054)
	arp=ethernet_packet+arp_pack()	
	s.send(arp)
	packet =  sr.recvfrom(4096)
	arp_unpack(packet)
default_gateway_mac()

# Creating an IP packet, Creating a header with checksum zero => calculating the checksum and embedding the checksum value in the packet 

def ip_pack(IHL = 5,VER = 4,TOS = 0,LEN = 0,offset = 0,TTL = 255,Chksm = 0,ID = random.randint(1,65536),Prot = socket.IPPROTO_TCP,Source_ip=Sourceip,destination_ip=destinationip):
	Source_ip = socket.inet_aton ( Sourceip )
	destination_ip = socket.inet_aton ( destinationip )
	IHL_VER = (VER << 4) + IHL
	ip_header = pack('!BBHHHBBH4s4s' , IHL_VER, TOS, LEN, ID, offset, TTL, Prot, Chksm, Source_ip, destination_ip)
	check=checksum(ip_header) # Calcullate the checksum of the IP header
	ip_header = pack('!BBHHHBBH4s4s' , IHL_VER, TOS, LEN, ID, offset, TTL, Prot, check, Source_ip, destination_ip)
	return ip_header

source_port=random.randint(1000,65000)
# Creating a TCP header, Creating a psuedo header => calculating the checksum of pseudo header, tcp header and data and embedding the checksum value in the packet 

def tcp_pack(tcp_source =source_port ,tcp_dest = 80,tcp_seq = 0,tcp_ack_seq = 0,tcp_doff = 5,tcp_fin = 0,tcp_syn = 0,tcp_rst = 0,tcp_Pseudo_head = 0,tcp_ack = 0,tcp_urg =0,tcp_window = 65500,check=0,tcp_urg_ptr=0,user_data=''):	
	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_Pseudo_head <<3) + (tcp_ack << 4) + (tcp_urg << 5)
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, check, tcp_urg_ptr)
	tcp_length = len(tcp_header) + len(user_data)
	Pseudo_head = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length); # Creating a pseudo header.
	Pseudo_head = Pseudo_head + tcp_header + user_data;
	check = checksum(Pseudo_head) # Calculating the checksum
	tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , check) + pack('!H' , tcp_urg_ptr)
	return tcp_header


# Defining the three way handshake. If the ack is lost, Retransmitting tha packet if no reply in 60 seconds and terminating session if no packet is recieved after 180 seconds. 

def handshake():
	syn_packet=ether_pack(dest_mac=mac)+ip_pack(LEN=40)+tcp_pack(tcp_seq=random.randint(30000,100000),tcp_syn=1)+''
	send_s.send(syn_packet)
	send_time=time.time()# Calculating the time at which packet is sent
	packet=recv_s.recvfrom(4096)
	if (time.time()-send_time<60): # Calculating the time at which packet is recieved, verifing if the difference is 60 seconds.
		IPlength = ip_unpack(packet)	
		seq,ack,dat,flags,check=tcp_unpack(packet,IPlength)
		ack_packet=ether_pack(dest_mac=mac)+ip_pack(LEN=40)+tcp_pack(tcp_seq=ack,tcp_ack_seq=seq+1,tcp_ack=1)+''
		send_s.send(ack_packet)
	elif (time.time()-send_time<180):
		sys.exit()
	else:
		handshake() # If its less than 60 seconds, accepting the packet and if data not recieved in 60 seconds reinitiate the handshake.
	return ack,seq+1

# Defining the unpacking of IP packet, taking the length of IP packet as return value. this is used as input to TCP unpacking to seperate the data from the total packet.

def ip_unpack(packet):
	global d_addr 
	packet = packet[0]	 
	ip_header = packet[0:20]
	ip_h = unpack('!BBHHHBBH4s4s' , ip_header)
	ver_ihl = ip_h[0]
	version = ver_ihl >> 4 # Right shift the bits to seperate version from the combined value of IHL and version
	ihl = ver_ihl & 0xF
	ip_h_length = ihl * 4
	ttl = ip_h[5]
	protocol = ip_h[6]
	s_addr = socket.inet_ntoa(ip_h[8]);
	d_addr = socket.inet_ntoa(ip_h[9]);
	return ip_h_length

# Defining the unpacking of TCP packet, taking ip length as input
packets = {}
def tcp_unpack(packet,ip_h_length):
	global dest_port
	packet = packet[0]
	tcp_header = packet[ip_h_length:40]
	check = checksum(tcp_header) # Calculating the checksum of TCP packet
	tcph = unpack('!HHLLBBHHH' , tcp_header)
 	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 2
	tcp_flags=tcph[5]
	tcp_wnd=tcph[6]
	urg_ptr = tcph[8]
	h_size = ip_h_length + tcph_length # Calculating the header size. data is considered from the point to header lenght to the end.
	data_size = len(packet) - h_size
	data = packet[h_size:]
	Test_flags = '{0:08b}'.format(tcp_flags)
	Test_tcp = packet[ip_h_length:] # Calculating the checksum to verify the incoming packet, the packet is appended with the pseudo header with the inputs from the unpacket TCP header.
	Test_length=len(Test_tcp)		# then calculating the checksum of the packet as done while packing, In this process if the chechsum obtained is "0", the recieved packet is error free.
	Test_psd = pack('!4s4sBBH' , dest_address , source_address , placeholder , protocol , Test_length)
	Test_packet = Test_psd+Test_tcp
	#print("checksum",checksum(Test_packet))
	check = checksum(Test_packet)
	return sequence,acknowledgement,data,tcp_flags,check

try:
	seq,ack=handshake()
except struct.error:
	print("Improper arguments passes while packing or unpacking of data-Please try again")
except socket.error:
	print("A unknown socket error has occured-Please try again")
	sys.exit()

# Defining the HTTP GET request, the fields like URL are taken as input from the system arguements passed at the runtime. 
user_data ="GET " +extension+" HTTP/1.0\r\nHost: " +URL+"\r\nConnection: keep-alive\r\n\r\n"
global cwnd

# Defining function that accepts the data based on the congestion window. 
global test 
def get_data(user_data):
	cwnd = 1
	http_pack=ether_pack(dest_mac=mac)+ip_pack(LEN=40+len(user_data))+tcp_pack(tcp_seq=seq,tcp_ack_seq=ack,tcp_ack=1,tcp_Pseudo_head=1,user_data=user_data)+user_data
	send_s.send(http_pack)
	test = ack
	ack_packet=http_pack
	packet=recv_s.recvfrom(4096)	
	while cwnd <= 1000: # The packets are recieved untill the, the maximum congestion window is reached, after which it is reduced to 1 by the "if" condition defined below. 
		packet=recv_s.recvfrom(4096)
		IPlength = ip_unpack(packet)
		seq1,ack1,dat,flags,check = tcp_unpack(packet,IPlength)
		req_dat=len(dat)
		if seq1 != test:
			send_s.send(ack_packet)
			continue
		g = '{0:08b}'.format(flags) # splitting the Flags recieved in the packet to binary so that Reset and Fin packets are identified and necessary action be taken accordingly.
		if cwnd + 1 > 0 and cwnd < 1000: # checking if the congestion window is between 1 and 1000, then additive increase is followed.
                            cwnd = cwnd + 1
                else:
                            cwnd = 1 # Reducing the cwnd to one if increases by 1000
		if (check == 0) and (source_port==dest_port) and (Sourceip==d_addr)  : # Checking the value of checksum for verifing the authenticity of the packet.
                		if "HTTP/1.1" in dat: # Verifing if its the first packet which containes the verification code of the reply sent by server of the data
                        		if "HTTP/1.1 200 OK" in dat: # Checking if the requested page is available, if it is so, recieve code is 200 OK.
                                		index = dat.find('\r\n\r\n') + 4
                                		dat = dat [index:] # If the recieve code is "200 OK", the header part of the message is avoided and the rest data is appended to the output file
                                		packets[seq1] = dat
                                		f.write(str(dat))
					elif "HTTP/1.1 301 OK" in dat:
						print("Page permanently moved")
						sys.exit()
					elif "HTTP/1.1 40" in dat:
						print("Page not found")
						sys.exit()
                        		else:
                                		print("The page is not found or Redicted") # If the recieve code is not "200 OK", the program throws an error and breaks.
                                		sys.exit()
                		else:
                        		f.write(str(dat)) # if the packet is not the first packet, then directly the consistent data is appended to the file created.
                        		packets[seq1] = dat

		if g[7] == '1': # Detecting if a fin packet is recieved and triggering the ACk and FIN-ACK from the client side
			ack_packet=ether_pack(dest_mac=mac)+ip_pack(LEN=40)+tcp_pack(tcp_seq=ack1,tcp_ack_seq=seq1+1,tcp_ack=1)+''
			send_s.send(ack_packet)
			ack_packet=ether_pack(dest_mac=mac)+ip_pack(LEN=40)+tcp_pack(tcp_seq=ack1,tcp_ack_seq=seq1+1,tcp_fin=1,tcp_ack=1)+''
			send_s.send(ack_packet)
			Fin_ack_rcvd = recv_s.recvfrom(4096) # recieving the final acknowledgement for the FIN packet from the server and closing the program.
			break
		elif g[5] == '1': # Checking the Reset flag from the set of flags recieved. If that is set to 1, break the code.
			break
		else:		# If the data does not contain fin or rst flags, ACK is sent with the ACK value as Seq + len of data
			ack_packet=ether_pack(dest_mac=mac)+ip_pack(LEN=40)+tcp_pack(tcp_seq=ack1,tcp_ack_seq=seq1+len(dat),tcp_ack=1)+''
			test = seq1+req_dat
			send_s.send(ack_packet)
			
# Actual function call for the recieving data
try:
	get_data(user_data)
except struct.error:
	print("Improper arguments passes while packing or unpacking of data-Please try again")
except socket.error:
	print("A unknown socket error has occured-Please try again")
	sys.exit()
