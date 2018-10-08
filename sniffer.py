#!/usr/bin/python2.7
import socket
import os
import struct
from ctypes import *

print "Simple Python Packet Sniffer"
# host to listen on
host   = raw_input("Host:")
ver    = raw_input("Would you like verbose output?[y/n]:")

class IP(Structure):

    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte, 8),
        ("len",           c_ushort, 16),
        ("id",            c_ushort, 16),
        ("offset",        c_ushort, 16),
        ("ttl",           c_ubyte, 8),
        ("protocol_num",  c_ubyte, 8),
        ("sum",           c_ushort, 16),
        ("src",           c_uint, 32),
        ("dst",           c_uint, 32),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)    

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # human readable IP addresses
        #self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        #self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
        ("src",           c_uint32),
        ("dst",           c_uint32)  

        self.src_address = socket.inet_ntoa(struct.pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I",self.dst))
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP 
else:
    socket_protocol = socket.IPPROTO_ICMP
    
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

try:
    sniffer.bind((host, 0))
except socket.error:
    print "Unable to assign IP address:%s" % host

print "Sniffing..."

# we want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're on Windows we need to send some ioctls
# to setup promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
    
        # read in a single packet
        raw_buffer = sniffer.recvfrom(65565)[0]
    
        # create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:32])
        if ver == "y":
          print "Raw values:"
          print "%s" % ip_header
          print "  "
          print "%s" % raw_buffer
          print "   "
          print "Human readable form:"
          print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
          print "   "
        else:
          print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
          print " "
        
except KeyboardInterrupt:
    # if we're on Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
except SocketError:
    print "Couldn't assign IP address:%s" % host
