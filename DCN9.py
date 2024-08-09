#--------------------------------------------------------#
# Datacenter routing optimization method to save power consumption  #
# Created by Ali Malik and mohammed ridha                           #
#--------------------------------------------------------#
import threading
from threading import Thread
import os
import json
#------------------------------
import struct
import pox.lib.packet as pkt
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.openflow.discovery import Discovery
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.vlan import vlan
from pox.lib.packet.ipv4 import ipv4
import pox.lib.util as poxutil 
from pox.lib.revent.revent import EventMixin, Event
import pox.openflow.spanning_tree as spanning_tree
from pox.lib.util import dpidToStr
from pox.lib.util import dpid_to_str  
from pox.openflow.discovery import launch
#from monitoring2 import status_dict
#from pox.lib.recoco import Timer
import pox.openflow.nicira as nx
import networkx as netx
#from .monitoring2 import _install_monitoring_path
import time
import datetime
from datetime import datetime
from itertools import tee#, izip
import numpy as np
from random import randint
import sys
#import networkx as nx
import ast
import sched
import threading
#from threading import Timer
import fnss
from fnss.units import capacity_units, time_units
import fnss.util as util
import collections
import copy
from collections import Counter, defaultdict
import csv
from collections import namedtuple

from queue import Queue
#------------------------------------------------------
from .disjoint_paths import edge_disjoint_shortest_pair
#---------------------------------------------------------------------------------------------
request_queue = Queue()
delay_between_requests = 2  # in seconds

status_dict = {}
indicator = False                                                # boolean variable to check the state of prediction and polling functions
SUM = 0
counter = 0                                                      # to count the number of requests of the state of the ports
h_p = 0 
my_switches= {}      
CC = 0       
clear_do = 0
log = core.getLogger()                                           # the core is ready
mac_map = {}                                                     # the map of the mac
switches = {}                                                    # topology's switches
myswitches=[]                                                    # list of the swiches
adjacency = defaultdict(lambda:defaultdict(lambda:None))         # adjacency matrix
ori_adjacency = defaultdict(lambda:defaultdict(lambda:None))  
current_p=[]                                                  
#installed_path={}
G = netx.DiGraph() 
G1 = netx.DiGraph()                                                # initiate the graph G to maintain the network topology
sum_1 = 0
c = 1
counter2 = 0
counter3 = 0
rt = 0
rt2 = 0
ki = True
util_val = []
path_port1 = []
path_port = []
gap = False
Payload = namedtuple('Payload', 'pathId timeSent')
nodes = []                                                     # all the nodes inside our topology 
switches_info = defaultdict(lambda: defaultdict(int))          # Holds switches, ports, last seen bytes, defaultdic = ({dpid:{port_no:traffic,........},{dpid:{port_no:traffic,........},....}).
Links_ports = defaultdict(list)                                # This dictionary represents each switch-port equals which link  defaultdic = ({( dpid1,port_no):[pid1, dpid2],.....})
Links_utilization = defaultdict()                              # dictionary of the utility of links, # defaultdic = (dpid1, dpid2):utility,........)
monitored_paths = {}
monitored_paths2 = {}
Traffic_type = {}                                              # Traffic_type = {hash: 'ICMP', .....}
Traffic_pairs = {}                                             # Traffic_pairs = {hash: (host_x, host_y), ....}
#------------------------------------------------------
def _send_timer():
    global nodes
    #print ('This is my send_timer function ...')
    for n in nodes:
        #Sends out requests to the network nodes
        n.connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request())) 

#------------------------------------------------------------------------>
m = { 'h1' : ("00:00:00:00:00:01") , 'h2': ("00:00:00:00:00:02"), 'h3' : ("00:00:00:00:00:03") , 'h4' : ("00:00:00:00:00:04"), 'h5' : ("00:00:00:00:00:05"), 'h6' : ("00:00:00:00:00:06"), 'h7' : ("00:00:00:00:00:07"), 'h8' : ("00:00:00:00:00:08"), 'h9' : ("00:00:00:00:00:09"), 'h10' : ("00:00:00:00:00:0a"), 'h11' : ("00:00:00:00:00:0b"), 'h12' : ("00:00:00:00:00:0c"), 'h13' : ("00:00:00:00:00:0d"), 'h14' : ("00:00:00:00:00:0e"), 'h15' : ("00:00:00:00:00:0f"), 'h16' : ("00:00:00:00:00:10")}
ma = { 'h1' : 1 , 'h2': 2, 'h3' : 3 , 'h4' : 4, 'h5' :5, 'h6' : 6, 'h7' : 7, 'h8' : 8, 'h9' : 9, 'h10' : 10, 'h11' : 11, 'h12' : 12, 'h13' : 13, 'h14' : 14, 'h15' : 15, 'h16' : 16}
#------------------------------------------------------------------------>    
#------------------------------------------------------------------------>

Switch_Dictionary = { (1): 's1', (2): 's2', (3): 's3',(4): 's4', (5): 's5', (6): 's6', 
(7): 's7', (8): 's8', (9): 's9', (10): 's10', (11): 's11', (12): 's12', (13): 's13', (14): 's14',
(15): 's15', (16): 's16', (17): 's17', (18): 's18', (18): 's18', (19): 's19', (20): 's20', (21): 's21',
(22): 's22', (23): 's23', (24): 's24', (25): 's25', (26): 's26', (27): 's27', (28): 's28', (29): 's29',
(30): 's30', (31): 's31' , (32): 's32', (33): 's33', (34): 's34', (35): 's35', (36): 's36', (37): 's37',
(38): 's38', (39): 's39', (40): 's40', (41): 's41', (42): 's42', (43): 's43', (44): 's44', (45): 's45',
(46): 's46', (47): 's47', (48): 's48', (49): 's49', (50): 's50', (51): 's51',
(52): 's52', (53): 's53', (54): 's54', (55): 's55', (56): 's56', (57): 's57', (58): 's58',(59): 's59',
(60): 's60' , (61): 's61' , (62): 's62' , (63): 's63' , (64): 's64' , (65): 's65', (66): 's66',
(67): 's67', (68): 's68', (69): 's69', (70): 's70'}
#--------------------------------------------------------
Host_Dictionary = { '1': 'h1', '2': 'h2', '3': 'h3','4': 'h4', '5': 'h5', '6': 'h6', '7': 'h7', '8': 'h8', '9': 'h9', 'a': 'h10', 'b': 'h11', 'c': 'h12', 'd': 'h13', 'e': 'h14', 'f': 'h15', '0': 'h16'}
#------------------------------------------------------
Port_Dictionary = { (1): 'eth1', (2): 'eth2', (3): 'eth3',(4): 'eth4', (5): 'eth5', (6): 'eth6', (7): 'eth7', (8): 'eth8', (9): 'eth9', (10): 'eth10', (11): 'eth11', (12): 'eth12', (13): 'eth13', (14): 'eth14', (15): 'eth15', (16): 'eth16'}
#--------------------------------------------------------
Host_IP = { 'h1' : '10.0.0.1' , 'h2': '10.0.0.2', 'h3' : '10.0.0.3' , 'h4' : '10.0.0.4', 'h5' : '10.0.0.5', 'h6' : '10.0.0.6', 'h7' : '10.0.0.7', 'h8' : '10.0.0.8', 'h9' : '10.0.0.9', 'h10' : '10.0.0.10', 'h11' : '10.0.0.11', 'h12' : '10.0.0.12', 'h13' : '10.0.0.13', 'h14' : '10.0.0.14', 'h15' : '10.0.0.15', 'h16' : '10.0.0.16'}
#------------------------------------------------------
def _install_monitoring_path(self, source, destination, path, src_ip, dst_ip, match_ip):
	
        match = ofp_match_withHash()
        #log.debug("source %s", source)
        #match.dl_src = struct.pack("!Q", prev_path.src)[2:]                                    # convert dpid to EthAddr
        #mac_address_str = str(source)
        #log.debug("mac_address_str %s", mac_address_str)
        #mac_address_int = int(mac_address_str.replace(':', ''), 16)
        #log.debug("mac_address_int %s", mac_address_int)
        match.dl_src = struct.pack("!Q", source)[2:]
        #log.debug("dl_src %s", match.dl_src)


        
        #match.dl_dst = struct.pack("!Q", prev_path.dst)[2:]
        #match.dl_dst = struct.pack("!Q", destination)[2:]
        #mac_address_str_d = str(destination)
        #log.debug("destination : %s", destination )
        #mac_address_int_d = int(mac_address_str_d.replace(':', ''), 16)
        match.dl_dst = struct.pack("!Q", destination)[2:]
        #log.debug("dl_dst %s", match.dl_dst)
        
        match.dl_type = pkt.ethernet.IP_TYPE
        match.nw_proto = 253                                                                    # Use for experiment and testing
	#match.nw_dst = IPAddr("224.0.0.255")                                                   # IANA Unassigned multicast addres
        ###match.nw_dst = IPAddr(dst_ip)
        match.nw_dst = IPAddr("224.0.0.255")
        #log.debug("nw_dst %s", match.nw_dst )
        #match.nw_src = IPAddr(prev_path.__hash__())                             # path hash
        ###match.nw_src = IPAddr(src_ip)
        match.nw_src = IPAddr(match_ip)
        #log.debug("///////////////////////////nw_src %s", match.nw_src)
	
	
	#dst_sw = prev_path.dst
	#cur_sw = prev_path.dst
        #dst_sw = destination
        #cur_sw = destination
        #log.debug("dst_sw %s", dst_sw)
        msg = of.ofp_flow_mod()
        #msg.match.dl_type = pkt.ethernet.IP_TYPE
        #msg.match.nw_proto = 253   
        #msg.match.nw_src = IPAddr(src_ip)
        #msg.match.nw_dst = IPAddr(dst_ip)
        msg.match = match
        msg.idle_timeout = 10
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        #log.debug("Installing monitoring forward from switch %s to controller port", util.dpid_to_str(cur_sw))
        last_item = path[-1]                                                                # Access the last item in the list
        dst_sw = last_item[0]   
        #log.debug('========================================dst_sw: %s', dst_sw) 
        
        #log.debug('dst_sw: %s', dst_sw)                                                    # Retrieve the first value from the last item
        #log.debug('my_switches %s', my_switches)
        #switches[dst_sw].connection.send(msg)
        #self.connection.send(msg)
        
        my_switches[dst_sw].send(msg)
       
        
        
        intermediate_path = path[1:-1]   
        for i in intermediate_path:
            #log.debug('i : %s', i)
            msg = of.ofp_flow_mod()
            msg.match.in_port = (int(i[1]))
            #msg.match.in_port = of.OFPP_CONTROLLER
            #msg.priority=10
            msg.idle_timeout = 10                                                                              #OFP_FLOW_PERMANENT
            #msg.flags = of.OFPFF_SEND_FLOW_REM
            #msg.hard_timeout = 160                                                                            #20 minutes 
            #msg.data=event.ofp.data
            #msg.match.dl_src = dl_src
            #msg.match.dl_dst = dl_dst
            #msg.match = match
            ###msg.match.dl_type = pkt.ethernet.IP_TYPE
            ###msg.match.nw_proto = 253   
            ###msg.match.nw_src = IPAddr(match)
            ###msg.match.nw_dst = IPAddr("231.27.204.235")
            msg.match = match
            msg.actions.append(of.ofp_action_output(port = int(i[2])))
            #msg.buffer_id = buf
            #core.openflow.getConnection(int(i[0])).send(msg)
            #self.connection.send(msg)
            my_switches[i[0]].send(msg)
            
        '''    
        #To install the reversed path now
        reversed_path_port = path[::-1] 
        reversed_intermediate_path = path[1:-1]
        for j in reversed_intermediate_path:
            msg = of.ofp_flow_mod()
            match.dl_src = struct.pack("!Q", destination)[2:]
            log.debug("dl_src %s", match.dl_src)
            msg.idle_timeout = 10                                                                             #OFP_FLOW_PERMANENT
            msg.flags = of.OFPFF_SEND_FLOW_REM
            match.dl_dst = struct.pack("!Q", source)[2:]
            log.debug("dl_dst %s", match.dl_dst)
            msg.match = match
            msg.actions.append(of.ofp_action_output(port = int(j[1])))
            #msg.buffer_id = buf
            core.openflow.getConnection(int(j[0])).send(msg)
            #self.connection.send(msg)
            
        '''   
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#------------------------------------------------------------------------>
class ofp_match_withHash(of.ofp_match):
	##Our additions to enable indexing by match specifications
	#log.debug("ofp_match_withHash class has called")
        
               
        @classmethod
        def from_ofp_match_Superclass(cls, other):	
               match = cls()
		#log.debug("match instances is greating")
		#match.wildcards = other.wildcards
               match.in_port = other.in_port
               match.dl_src = other.dl_src
               match.dl_dst = other.dl_dst
               match.dl_vlan = other.dl_vlan
               match.dl_vlan_pcp = other.dl_vlan_pcp
               match.dl_type = other.dl_type
               match.nw_tos = other.nw_tos
               match.nw_proto = other.nw_proto
               match.nw_src = other.nw_src
               match.nw_dst = other.nw_dst
               match.tp_src = other.tp_src
               match.tp_dst = other.tp_dst
               #log.debug("the match is %s", match)
               #match.of_eth_src  = other.of_eth_src
               #atch.of_eth_dst = other.of_eth_dst
               return match
		
        def __hash__(self):
               #return hash((self.wildcards, self.in_port, self.dl_src, self.dl_dst, self.dl_vlan, self.dl_vlan_pcp, self.dl_type, self.nw_tos, self.nw_proto, self.nw_src, self.nw_dst, self.tp_src, self.tp_dst))
             return hash(( self.in_port, self.dl_src, self.dl_dst, self.dl_vlan, self.dl_vlan_pcp, self.dl_type, self.nw_tos, self.nw_proto, self.nw_src, self.nw_dst, self.tp_src, self.tp_dst))
		
        
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


class NewFlowEntry(Event):
    def __init__(self, path_port, match, src_mac, dst_mac, sw_src, sw_dst, src_ip, dst_ip, path):
        Event.__init__(self)
        self.match = match
        self.path_port = path_port
        self.sw_src = sw_src
        self.sw_dst = sw_dst
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.path = path

    def raiseEvent(self):
        # Implement the logic to raise the event here
        # You can print a message or perform any other actions as needed
        #00:00:00:00:00:01
        log.debug("NewFlowEntry event raised, match: %s, path_port: %s, sw_src: %s, sw_dst: %s, src_ip: %s, dst_ip: %s, path: %s" %(self.match,
        self.path_port, self.sw_src, self.sw_dst, self.src_ip, self.dst_ip, self.path))
        #log.debug("match: %s",self.match)
        #log.debug("path_port: %s",self.path_port)
        #log.debug("sw_src: %s",self.sw_src)
        #log.debug("sw_dst: %s",self.sw_dst)
        #log.debug("src_mac: %s",self.src_mac)
        #log.debug("dst_mac: %s",self.dst_mac)
        #log.debug("src_ip: %s",self.src_ip)
        #log.debug("dst_ip: %s",self.dst_ip)
        #log.debug("path: %s",self.path)
        
        path_port = self.path_port
        path = self.path	
        #log.debug("path %s", path)
        src_mac = self.src_mac
        #log.debug("src_mac %s", src_mac)
        dst_mac = self.dst_mac
        #log.debug("dst_mac %s", dst_mac)
        sw_src = self.sw_src
        sw_dst = self.sw_dst
        src_ip = self.src_ip
        dst_ip = self.dst_ip
        match = self.match
        status_dict[match.__hash__()] = []
        
        path_port_tuple = tuple(path_port)  
        if path_port_tuple not in monitored_paths:
            #monitored_paths[path_port_tuple] = set([match])
            #log.debug ('monitored_paths before instaling alternative path: %s', monitored_paths)
            #log.debug ('monitored_paths2 before instaling alternative path: %s', monitored_paths2)
            x = match.__hash__()
            
            monitored_paths[x] = path_port_tuple
            monitored_paths2[x] = path
            #log.debug ('monitored_paths after instaling alternative path: %s', monitored_paths)
            log.debug ('monitored_paths2 after instaling alternative path: %s', monitored_paths2)
            
        
        _install_monitoring_path(self,sw_src, sw_dst , path_port, src_ip, dst_ip, match.__hash__() )
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
class proactive(EventMixin):
  _eventMixin_events = set([NewFlowEntry,]) 

  @classmethod
  def raise_new_flow_event(cls, path_port, match, src_mac, dst_mac, src_switch, dst_switch, src_ip, dst_ip, path):
        new_flow_entry = NewFlowEntry(path_port, match, src_mac, dst_mac, src_switch, dst_switch, src_ip, dst_ip, path)
        new_flow_entry.raiseEvent()

  @classmethod    
  def proactive_path_installation(cls, path, pair):
    global ma
    global m
    global Host_IP
    global switches 
    global myswitches 
    #print ('########## ########## ########## ########## ########## ########## ########## ########## ########## ')
    log.debug ('This is the proactive_path_installation function to install an alternative path proactively')
    log.debug("link utilization-------------------------------------------------------------------->: %s", Links_utilization)
    log.debug("weight of the graph-------------------------------------------------------------------->: %s",list(G.edges().items()))
    reverse_path = path[::-1]
    log.debug('We are going to install the path %s', path)
    
    #log.debug('The path pairs are %s', pair)
    #log.debug('The mac of source host is %s', m[pair[0]])
    #log.debug('The int of source host is %s', ma[pair[0]])
    x_src = ma[pair[0]]
    h_s = m[pair[0]] 
    #log.debug('The mac of destination host is %s', m[pair[1]])
    #log.debug('The int of destination host is %s', ma[pair[1]])
    x_dst = ma[pair[1]]
    #print ("=====================================================================",ma[pair[1]])
    h_d = m[pair[1]]
    #print ("=====================================================================",m[pair[1]])
    #log.debug('As well as installing its reverse %s', reverse_path)
    in_ports = []
    out_ports = []
    src = path[0]
    dst = path[-1]
    pr = 0
    xr = 0
    #log.debug ("Source switch is %s", src)
    #log.debug ("Destination switch is %s", dst)
    for j in pairwise1(path):
        #log.debug ('the pair is %s', pair)
        #log.debug ("The output port is %s", adjacency[pair[0]][pair[1]])
        out_ports.append(adjacency[j[0]][j[1]])
    #print (ma[pair[1]])
    if x_dst % 2 == 0:
       #print ("True")
       pr = 4
    else: 
       #print ("False")
       pr = 3  
    out_ports.insert(len(out_ports), pr)                                            #4
    #log.debug ("out_ports are %s", out_ports)
    for i in pairwise1(reverse_path):
        #log.debug ('the pair is %s', pair)
        #log.debug ("The input port is %s", adjacency[pair[0]][pair[1]])
        in_ports.append(adjacency[i[0]][i[1]])
    
    if x_src % 2 == 0:
       #print ("True")
       xr = 4
    else: 
       #print ("False")
       xr = 3     
    in_ports.insert(len(in_ports), xr)                                               #3
    #log.debug ("in_ports are %s", in_ports)
    #match = ofp_match_withHash()
    
    for i in range (len(path)):
        #print ("in-ports -- out-ports are", in_ports[i], out_ports[i])
        msg = nx.nx_flow_mod()
        #print ("msg = nxx.nxx_flow_mod() is DONE")
        msg.idle_timeout = 10
        #msg.hard_timeout = 0
        msg.priority = 1000
        msg.flags = of.OFPFF_SEND_FLOW_REM
        #log.debug ('The source host (h_s) is %s', h_s)
        #log.debug ('The destination host (h_d) is %s', h_d)
        
        match = ofp_match_withHash()
        match.dl_src = EthAddr(h_s)
        match.dl_dst = EthAddr(h_d)
        
        msg.match.of_eth_src = EthAddr(h_s) #("00:00:00:00:00:01")
        #print ("msg.match.of_eth_src = EthAddr(h_s) is DONE")
        msg.match.of_eth_dst = EthAddr(h_d) #("00:00:00:00:00:10")#
        #msg.match = match
        x = match.__hash__()
        ch = x in Traffic_pairs.keys()
        if ch == False:
           Traffic_pairs[x] = pair
           Traffic_type[x] = "RTP"
        #log.debug ('x = match.__hash__() ---------------------- after install the alternative path %s', x)
        #monitored_paths2[x] = path 
        #log.debug (' Traffic_pairs ----------------------  %s',  Traffic_pairs)
        #log.debug (' Traffic_type ----------------------  %s',  Traffic_pairs)
        
        
        
        #print ("msg.match.of_eth_dst = EthAddr(h_d) is DONE")
        msg.actions.append(nx.nx_action_dec_ttl())
        #print ("msg.actions.append(nxx.nxx_action_dec_ttl()) is DONE")
        msg.actions.append(of.ofp_action_output(port = out_ports[i]))
        #print ("msg.actions.append(of.ofp_action_output(port = out_ports[i])) is DONE")
        core.openflow.sendToDPID(switches[path[i]].dpid, msg)
        #print ("core.openflow.sendToDPID(switches[p[i]].dpid, msg)")
        #print ("event.dpid is --> switches[p[i]].dpid = ", switches[path[i]].dpid)
    path_port = _get_path (path, src, dst, xr , pr) 
    #log.debug ('x_src %s', x_src) 
    #log.debug ('x_dst %s', x_dst)
    src_ip = Host_IP[pair[0]]
    dst_ip = Host_IP[pair[1]]
    #log.debug ('the path ports to raise new flow event %s', path_port)  
    #log.debug ('the swiches[dst] %s', switches [dst]) 
    #log.debug ('the swiches[src] %s', switches [src])
    #log.debug ('the src_ip %s', src_ip)
    #log.debug ('the dst_ip %s', dst_ip)
    #log.debug ('Installation is completed for the path %s', path)
    #print ('########## ########## ########## ########## ########## ########## ########## ########## ########## ')
    #monitored_paths[path_port_tuple].add(match)
    #monitored_paths2[path].add(match)
    #raise_new_flow_event(path_port, match, h_s, h_d, switches[src], switches[dst], src_ip, dst_ip, path)
    #new_flow_entry = NewFlowEntry(path_port, match, switches[src], switches[dst], src, dst, src_ip, dst_ip, path)
    # Raise the event
    #new_flow_entry.raiseEvent()
    my_switch = proactive()

    # Call the method on the my_switch instance
    my_switch.raise_new_flow_event(path_port, match,  switches[src], switches[dst],src, dst, src_ip, dst_ip, path)
    #log.debug ('the event is raised, of new flow entry %s', path)
       #-------------------
    
    for i in range (len(path)):
        #print ("reversed path installation in-ports -- out-ports are", in_ports[i], out_ports[i])
        #self._install(in_ports[i], out_ports[i])
        msg = nx.nx_flow_mod()
        #print ("msg = nxx.nxx_flow_mod() is DONE")
        msg.idle_timeout = 10
        #msg.hard_timeout = 0
        msg.priority = 1000
        msg.match.of_eth_src = EthAddr(h_d) #("00:00:00:00:00:10")
        #print ("msg.match.of_eth_src = EthAddr(00:00:00:00:00:06) is DONE")
        msg.match.of_eth_dst = EthAddr(h_s) #("00:00:00:00:00:01")
        #print ("msg.match.of_eth_dst = EthAddr(00:00:00:00:00:01) is DONE")
        msg.actions.append(nx.nx_action_dec_ttl())
        #print ("msg.actions.append(nxx.nxx_action_dec_ttl()) is DONE")
        msg.actions.append(of.ofp_action_output(port = in_ports[i]))
        #print ("msg.actions.append(of.ofp_action_output(port = rev_ports[i])) is DONE")
        core.openflow.sendToDPID(switches[reverse_path[i]].dpid, msg)
        #print ("core.openflow.sendToDPID(switches[rev_p[i]].dpid, msg)")
        #print ("event.dpid is --> switches[rev_p[i]].dpid = ", switches[reverse_path[i]].dpid)
    log.debug ('Installation is completed for the reversed path %s', path)
    #path_port = _get_path (path, src, dst, mac_map[str(packet.src)][1], mac_map[str(packet.dst)][1])
    log.debug (' Traffic_pairs after installing an alternative path proactively:  %s',  Traffic_pairs)
    log.debug (' Traffic_type after installing an alternative path proactively:  %s',  Traffic_type)
    #print ('########## ########## ########## ########## ########## ########## ########## ########## ########## ')
#------------------------------------------------------
def _handle_portstats_received(event):
      """
      Handler to manage port statistics received Args: event 
      Event listening to PortStatsReceived from openflow
      """
      global Links_utilization #
      global G,G1
      #G = G1.copy()
      global counter
      global h_p
      global Links_ports    
      now = datetime.now()
      global c
      global ki
      global gap
      G_edges = G.edges()     #      
      G_weight = list(G_edges.items())#
      v = list(Links_utilization.items())
      topo_link = list(Links_utilization.keys())   #
      current_state_byte = 0
      last_state_bytes = 0 
      
      

      for f in event.stats:
          
          #for attr_name in dir(f):
            #if not attr_name.startswith("__"):  # Exclude special attributes
               #attr_value = getattr(f, attr_name)
               #log.debug(f"{attr_name}: {attr_value}")
          
          if int(f.port_no) < 5  :                                                                 # used from hosts and switches interlinks, 34525,65534
              current_state_bytes =  f.tx_bytes                                                        # transmitted and received (f.rx_bytes )
              try:
                  last_state_bytes = switches_info[int(event.connection.dpid)][int(f.port_no)]         #defaultdic = ({dpid:{port_no:traffic,........},{dpid:{port_no:traffic,........},.....})
              except:
                  last_state_bytes = 0
              estim_l_utility = (current_state_bytes - last_state_bytes)                               #calculate the current utility of the links
              if gap == True:
                 estim_l_utility = estim_l_utility /10
              else:
                 estim_l_utility = estim_l_utility /2
              estim_l_utility = (((estim_l_utility)*8)/1024)/1024                                      # convert the value from byte to Mbit
              linlk_Capacity_Mbit = 10                                                              # link capacty is 1Mbit
              estim_l_utility = (estim_l_utility/linlk_Capacity_Mbit)                                  #link utility estimistion in %
              estim_l_utility = float(format(estim_l_utility, '.2f'))
              
              if estim_l_utility >= 0:
                  if Links_ports [event.dpid, f.port_no] != []:                
                     utility=list(Links_utilization.values())                                        
                     utility = list(np.array(utility))
                     header = (Links_utilization.keys())                 
                     headers = []
                     for j in header:
                         s = str(j)
                         s = s.replace(',', ' ')
                         headers.append(s)                  
                     counter = counter +1
                     if counter >= 150:      
                      if counter/64 == int(counter/64):                  
                        with open('output.csv', 'a') as m:                             
                           if h_p == 0:                               
                               m.write(datetime.now().strftime(format = '%H:%M:%S,'))
                               m.write(str(headers))
                               m.write('\n')
                               h_p = 1                               
                           m.write(datetime.now().strftime(format = '%H:%M:%S,'))
                           m.write(str(utility)[1 : -1])                
                           m.write('\n')                                      
                     pair = Links_ports [event.dpid, f.port_no]               # pair = (s,p)
                     pair = tuple(pair)
                     Links_utilization [(pair)] = estim_l_utility
                     
              switches_info[int(event.connection.dpid)][int(f.port_no)] = (current_state_bytes)  
      #log.debug("link utilization: %s", Links_utilization)
      for p in topo_link:
         #print ('p',p)
         #sum_uti = 0
         for i in range (len (G_weight)):
             if p == topo_link[i]:
                uti =  Links_utilization[(topo_link[i])]
                #log.debug("the utility : %s", uti)
                for j in range (len(G_weight)):
                    if p == G_weight[j][0]:
                       z = G_weight[j][0]
                       #log.debug("G_weight[j][0]: %s", G_weight[j][0])
                       if uti < 0.9 and uti > 0:
                          G[z[0]][z[1]]["weight"] = 499 - (0.9 - uti)                               # less than threshold value
                          #log.debug("the utility between 0.98 and 0: %s", uti)
                          #log.debug("weight of the graph: %s",list(G.edges().items())) 
                       elif uti == 0:
                          G[z[0]][z[1]]["weight"] = 700                                             # initial value
                       else:
                          G[z[0]][z[1]]["weight"] = 1000                                            # more than threshold value
                       #if c == 20:
                       #utiliz = []
                       #utiliz.append(uti)
                       G[z[0]][z[1]]["Utilization"] =  uti
      #log.debug("weight of the graph: %s",list(G.edges().items()))
      #log.debug("weight of the graph: %s",list(G.edges().items()))      
      #export graph infprmation to csv file
      '''
      now = datetime.now()
      header1 = ['prefer path',now.strftime("%H:%M:%S")]
      header2 = ['graph weight',now.strftime("%H:%M:%S")]
      header3 = ['link utilization',now.strftime("%H:%M:%S")]
      with open('information.csv', 'a', encoding='UTF8') as f:
          now = datetime.now()
          writer = csv.writer(f)
          #write the header
          #writer.writerow(header1)
          # write multiple rows                 
          #writer.writerow(sp) 
          writer.writerow(header2)               
          writer.writerow(G_weight)
          writer.writerow(header3) 
          writer.writerow(v) 
      ''' 
#------------------------------------------------------     
#------------------------------------------------------
def pairwise1(iterable):
         a, b = tee(iterable)
         next(b, None)
         return zip(a, b)

#------------------------------------------------------------------------------------------------------------------------------------
def _get_raw_path(src,dst):                                                                         #8
  global G  
  global Links_utilization
  now = datetime.now()
  x = G.edges()
  x = list(x.items())
  v = list(Links_utilization.items())
  y = list(Links_utilization.keys())
  sp = []
  dis_joint = []                                                                                        # To store the computed shortest path
  sp = netx.shortest_path(G, source=src, target=dst, weight = 'weight')                                 # --> [1,2,3,4]
  #dis_joint = edge_disjoint_shortest_pair(G, src, dst)
  #sp = dis_joint[0]
  log.debug("The path found by Dijkstra algorithm is : %s", sp)
  #log.debug("time is in an instant %s",datetime.now())
  #log.debug("The path found by Dijkstra: %s", sp)
  #print ('The two disjoint paths are ---> ', edge_disjoint_shortest_pair(G, src, dst))
  #print ('The first disjoint is', dis_joint[0])
  #print ('The second disjoint is', dis_joint[1])
  #export pathis to draw grath load in the external monitor.py file
  with open("paths.txt", "a") as output:
    now = datetime.now()
    output.write(str(now.strftime("%H:%M:%S")))
    output.write(str(sp)) 
    output.write('\n') 
  return sp
#------------------------------------------------------
#------------------------------------------------------
def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports
  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[1]:
      return False
  return True
#------------------------------------------------------
#------------------------------------------------------
def _get_path (path, src, dst, first_port, final_port):                                                 # 9                                      
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]                                                                        #from server to the switch
  r.append((dst,in_port,final_port))
  assert _check_path(r), "Illegal path!"                                                               # 10                                                          
  return r
  
#------------------------------------------------------
#-----------------------------------------------------------------------
def process_queue():
       while True:
           request_data = request_queue.get()
           if request_data is None:
             break  # Stop processing when None is encountered
           port, host_s, host_d, src_switch, packet, path, x = request_data
           #log.debug("Process_queue() has received request: port: %s, host_s: %s, host_d: %s, src_switch: %s,  path: %s, x : %s" %(port, host_s, host_d, src_switch, path, x))
           #log.debug("we are processing the requests in the queue , right know")
           #log.debug(f"currently the Process_queue() is processing the request {x} in the queue request. ")  # Print the processed request
           log.debug(f"current Queue size: {request_queue.qsize()}")  # Print the current queue size
           switch_instance = Switch()  # Create an instance of the Switch class
           #switch_instance.Check_class(port, host_s, host_d, src_switch, packet, path, x)
           switch_instance.Collect(port, host_s, host_d, src_switch, packet, path, x)
           #Check_class(port, host_s, host_d, src_switch, packet, path, x)
           time.sleep(delay_between_requests)
  #--------------------------------------------------------------------------------------
#------------------------------------------------------

#------------------------------------------------------
#------------------------------------------------------

class Switch (EventMixin):                                                                   # 3
  _eventMixin_events = set([NewFlowEntry,])                                                  # @@@@                                                
  global G
  global monitored_paths                                                                     #@@@@@@
  global monitored_paths2
  queue_thread = threading.Thread(target=process_queue)
  queue_thread.start()
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None                                                                              # time of connection
    self.PathDelay = None                                                                                  # @@@ Create an instance of the l2.multi class *##############################################*


  def __repr__ (self):
    return dpid_to_str(self.dpid)
    

		        
  # send OPF.mod mesage
  def _install (self,match, dl_src, dl_dst, path_port, p, buf = None):                                     # 11
    #####log.debug("install is called to install rule at %s",self.dpid)
    #####log.debug("source switch is %s, and destination switch is %s",dl_src,dl_dst)
    for i in path_port:
        msg = of.ofp_flow_mod()
        msg.match.in_port = (int(i[1]))
        msg.priority = 10
        msg.idle_timeout = 10                                                                              #OFP_FLOW_PERMANENT
        msg.flags = of.OFPFF_SEND_FLOW_REM
        #msg.hard_timeout = 160                                                                            #20 minutes 
        #msg.data=event.ofp.data
        #msg.match.dl_src = dl_src
        #msg.match.dl_dst = dl_dst
        msg.match = match
        msg.actions.append(of.ofp_action_output(port = int(i[2])))
        msg.buffer_id = buf
        #core.openflow.getConnection(int(i[0])).send(msg)
        #self.connection.send(msg)
        my_switches[i[0]].send(msg)
        #log.debug(" switches[i[0]]:%s", switches[i[0]])
        #log.debug(" switches:%s", switches)
    #To install the reversed path now
    '''
    reversed_path_port = path_port[::-1] 
    for j in reversed_path_port:
         msg = of.ofp_flow_mod()
         #msg.data = even.ofp
         msg.match.in_port = (int(j[2]))
         #msg.priority=10
         msg.idle_timeout = 10                                                                            #OFP_FLOW_PERMANENT
         msg.flags = of.OFPFF_SEND_FLOW_REM
         #msg.hard_timeout = 160                                                                         #20 minutes 
         msg.match.dl_src = dl_dst
         log.debug("msg.match.dl_src %s",msg.match.dl_src)
         log.debug("dl_dst %s",dl_dst)
         msg.match.dl_dst = dl_src
         log.debug("dl_src %s",dl_src)
         msg.actions.append(of.ofp_action_output(port = int(j[1])))
         msg.buffer_id = buf
         core.openflow.getConnection(int(j[0])).send(msg)
         #self.connection.send(msg)
     '''
     
  def Check_class (self, port, host_s, host_d, src_switch, packet, path, x):
      #global List_of_Sources
      global Switch_Dictionary
      global Host_Dictionary
      global Port_Dictionary
      global Traffic_type
      global Traffic_pairs
      global monitored_paths
      global monitored_paths2
      #log.debug('Hi, we are inside the Check_class function right now to classify the flow with hash %s', x)
      
      #global Flow_global_view
      #L =[]
      #SW = []
      #Temp_link_to_G1 = []
      #Traffic = []                                              # The list represents the type of traffic on each link whether ICMP, UDP or TCP, it can can multiple ones.
      #MM = True
      if x in monitored_paths:
         #log.debug ('Traffic_type is: %s',Traffic_type)
         #log.debug("monitored_paths are: %s", monitored_paths)
         #log.debug("monitored_paths2 are: %s", monitored_paths2)
         prt = Port_Dictionary[port]
         pair = [host_s, host_d]
         #log.debug ("the pair is: %s", pair)
         #log.debug ('The path is: %s ', path)
         if os.stat('/home/mohammed/monitor_rtp.pcapng').st_size != 0:
            #print ("############################################################")
            #log.debug ("*************** Monitoring File is not Empty ***************")
            #print ("############################################################")
            pass
         if os.stat('/home/mohammed/monitor_rtp.pcapng').st_size == 0:
            #if os.stat('/home/ali/pox/monitor_rtp.pcapng').st_size == 0:
            #log.debug ("*************** Sorry, The Monitor File is Empty now ***************")
            return
         else:
             #f= open('/home/ali/pox/test.json')
             f= open('/home/mohammed/pox-halosaur/test.json')
             #log.debug ("$$$$$$$$$$$$$ ... We are inside Check_class () function ... $$$$$$$$$$$$$")
             #cmd2 = ('tshark -r monitor_rtp.pcapng -T json > test.json')                                             #conver the pcapng to json
             cmd2 = ('tshark -r /home/mohammed/monitor_rtp.pcapng -T json > test.json')                              #conver the pcapng to json
          
             os.system(cmd2)
             #print "%%%%%%%%%%%%%%%%%%%%%%%%%% Pcapng is converted to Json now %%%%%%%%%%%%%%%%%%%%%%%%%%"
             try:
                data = json.load(f)
                print ("*************** Json is loaded now ***************")
                data1= json.dumps(data)
                print ("*************** Json is dumped now ***************")
                data2= json.loads(data1)
                #print("Loaded JSON Data:", data)
                #print("Re-dumped JSON Data:", data1)
                #print("Reloaded JSON Data:", data2)
             except json.JSONDecodeError as e:
                print("Error decoding JSON:", e)
                
             except FileNotFoundError:
                print("Json File not found.")
          
             f.close()
             #Flog.debug ('We closed JSON file safely ...')
             if "sip" in data1:
                 Traffic_type[x] = 'SIP'
                 log.debug ("############## ... We found SIP ... ##################")
                 pkt_type = 'SIP'
             elif "5004" in data1:
                 Traffic_type[x] = 'RTP'
                 log.debug ("############## ... We found RTP ... ##################")
                 pkt_type = 'RTP'
             elif "icmp" in data1:
                 Traffic_type[x] = 'ICMP'
                 log.debug ("############## ... We found ICMP ... ##################")
                 pkt_type = 'icmp'
             elif "udp" in data1:
                 Traffic_type[x] = 'UDP'
                 log.debug ("############## ... We found UDP ... ##################")
                 pkt_type = 'udp'
             elif "tcp" in data1:
                 Traffic_type[x] = 'TCP'
                 log.debug ("############## ... We found TCP ... ##################")
                 pkt_type = 'udp'
             else:
                 log.debug ("############## ... We can not found protocol ... ##################")
             #with open('/home/ali/pox/test.json', 'r+') as v:
             with open('/home/mohammed/pox-halosaur/test.json', 'r+') as v:
                 v.truncate(0)
             #with open('/home/ali/pox/monitor_rtp.pcapng', 'r+') as m:
             with open('/home/mohammed/monitor_rtp.pcapng', 'r+') as m:
                 m.truncate(0)
         #for k, v in Traffic_pairs.items():
          #if v == pair:
             #log.debug("---------------------v:%s",v)
             #log.debug("---------------------k:%s",k)
             #log.debug("---------------------x:%s",x)
             
             #Traffic_type[k] = Traffic_type[x]
         #log.debug ('Traffic_type is: %s',Traffic_type)
         #log.debug("monitored_paths are: %s", monitored_paths)
         #log.debug("monitored_paths2 are: %s", monitored_paths2)
         #log.debug (" We are done ...")
      else:
         #log.debug (" x not in monitored_paths: ...................................")
         pass
         
         
      #---------------------------------  
      #request_queue.put((port, host_s, host_d, src_switch, packet, path, x))  # Enqueue the request for processing
       #---------------------------------  
      '''
      Marker = False
      if bool (Flow_global_view) == True:
                print ("The dict is not empty...")
                Traffic.append(pkt_type)
                for x in Flow_global_view.keys():
                        print ('x', x)
                        print ('pair', pair)
                        if set(x) == set(pair):
                                print ("the path already exists, probably the reversed path...")
                                Marker = True
                if Marker == False:
                        print ("We have got a new path to add ...")
                        for i in range (len(path)):
                                SW.append(Switch_Dictionary[path[i]])
                                #print "The path as switches is: ", SW
                        L = SW #path
                        L.insert(0,pair[0])
                        L.insert(len(L),pair[1])
                        Flow_global_view [tuple(pair)] = L #SW #path
                        print (Flow_global_view)
                        #print "#2 The whole path from host to host is", L
                        for pair in self.pairwise(L):
                            Temp_link_to_G1.append(pair)
                        print (Temp_link_to_G1)
                        #for i in range (len(Temp_link_to_G1)):
                        for i in Temp_link_to_G1:
                                 if G1.has_edge(i[0], i[1]) == True:
                                        xxx = []
                                        #yyy = []
                                        print ("The link", i, "is already exist in G1")
                                        G1[i[0]][i[1]]['weight'] = G1[i[0]][i[1]]['weight'] + 1
                                        xxx.append(pkt_type)
                                        G1[i[0]][i[1]]['Traffic'] = G1[i[0]][i[1]]['Traffic'] + xxx
                                 if G1.has_edge(i[0], i[1]) == False:
                                        G1.add_edge(i[0],i[1], weight = 1, Traffic = Traffic)  #weight =1 for the new links 
      if bool (Flow_global_view) == False:
                  #print "The dict is empty now ..."
                  Traffic.append(pkt_type)
                  for i in range (len(path)):
                          SW.append(Switch_Dictionary[path[i]])
                          #print "The path as switches is: ", SW
                  L = SW #path
                  L.insert(0,pair[0])
                  L.insert(len(L),pair[1])
                  Flow_global_view [tuple(pair)] = L #SW #path
                  print (Flow_global_view)
                  for pair in self.pairwise(L):
                      Temp_link_to_G1.append(pair)
                  print (Temp_link_to_G1)
                  G1.add_edges_from(Temp_link_to_G1, weight=1, Traffic = Traffic) # add the links of the computed path to G1 with Weight = 1 (initial case)
		  #fig = plt.figure()
		  #fig.canvas.set_window_title("The Current View of Abilene Flow")
		  #pos = netx.spring_layout(G1, scale=2)
		  #edge_labels = gx.get_edge_attributes(G1, 'Traffic')
		  #gx.draw_networkx_edge_labels(G1, pos, edge_labels)
		  #gx.draw_networkx(G1, with_labels = True, nodecolor='r', edge_color='b')
		  #gx.draw_networkx(G1)
		  #plt.savefig("Graph.png", format="PNG")
      print ("Graph-Flow at the moment --> ", G1.edges(data=True))
      '''
  #--------------------------------------------------------------------------------------
  #-----------------------------------------------------------------------
  #def process_queue():
       #while True:
       #x = request_queue.get()
       #if x is None:
          #break  # Stop processing when None is encountered
         
       #self.Check_class(port, host_s, host_d, src_switch, packet, path, x)
       #time.sleep(delay_between_requests)
  #--------------------------------------------------------------------------------------
    #-----------------------------------------------------------------------
  def Collect (self, port, host_s, host_d, src_switch, packet, path, x):
      #global List_of_Sources
      global Traffic_pairs
      global Switch_Dictionary
      global Host_Dictionary
      global Port_Dictionary
      
      scheduler = sched.scheduler(time.time, time.sleep)
      #log.debug ('Hi, we are inside the Collect function right now to classify the flow with hash %s', x)
      prt = Port_Dictionary[port]
      #log.debug("the switch is: %s, the port is: %s"%(Switch_Dictionary[src_switch],prt))
      
      
      # Create the capture file
      capture_file_path = '/home/mohammed/monitor_rtp.pcapng'
      open(capture_file_path, 'w').close()
      cmd = ('echo "123" | sudo -S tshark -c 2 -w ' + capture_file_path + ' -i ' + Switch_Dictionary[src_switch] + '-' + prt)
      #cmd =('tshark -c 2 -w monitor_rtp.pcapng -i'+Switch_Dictionary[src_switch]+ '-' +prt)
      #cmd =('tshark -c 2 -w /home/mohammed/pox-halosaur/monitor_rtp.pcapng -i'+Switch_Dictionary[src_switch]+ '-' +prt)
      t = threading.Thread(target=os.system, args=(cmd,))
      t.start()
      
      
      #if os.stat('/home/ali/pox/monitor_rtp.pcapng').st_size != 0:
      
      #if os.stat('/home/mohammed/monitor_rtp.pcapng').st_size != 0:
         #print ("############################################################")
         #log.debug ("*************** Monitoring File is not Empty ***************")
         #print ("############################################################")
         
      #with open('/home/mohammed/monitor_rtp.pcapng', 'r') as f:
               #file_content = f.read()
               #log.debug("Monitoring File Content:\n%s", file_content)
               #log.debug("Monitoring File is not empty")
  
      scheduler.enter(1, 1, self.Check_class, (port, host_s, host_d, src_switch, packet, path, x))
      t = threading.Thread(target = scheduler.run)
      t.start()
      #scheduler.run()
      #core.callDelayed(20, self.Check_class, port, host_s, host_d, src_switch, packet, path)
         
   #-----------------------------------------------------

  def _handle_PacketIn (self, event):                                                       # receive all the node requaste packet in   #7     
    #log.debug (" Packet In event")
    global G, current_p
    global SUM
    global monitored_paths
    global monitored_paths2
    global Switch_Dictionary
    global Host_Dictionary
    global Port_Dictionary
    
    
    def drop ():
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None                                                          # Mark is dead
        msg.in_port = event.port
        self.connection.send(msg)
    packet = event.parsed
       
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    if packet.effective_ethertype == pkt.ethernet.IP_TYPE:
       orig_ip = event.parsed.find('ipv4')
       ip_info = str(orig_ip)  # Convert the ipv4 object to a string
       lines = ip_info.split('\n')  # Split the string into lines
    
       for line in lines:
          if " l:" in line:
            length_value = int(line.split(" l:")[1].split()[0])  # Extract length value
            #log.debug('Packet In Handling: IP_Packet Length: %d', length_value)
            break  # Exit the loop after finding the correct line
       #packet_length = orig_ip.total_length
       #log.debug('Packet In Handling: IP_Packet Length: %s', packet_length)
       #icmp_payload_length = orig_ip.total_length - orig_ip.header_length 
       #if orig_ip.total_length > 500:       
       #if icmp_payload_length > 500:                                            
       #log.debug('Packet In Handeling: IP_Packet========================================================: %s', orig_ip)
       src_ip = orig_ip.srcip                                                                  
       dst_ip = orig_ip.dstip                                                                  
       #log.debug('Source IP===================================================: %s, Destination IP: %s', src_ip, dst_ip)
       orig_tcp = orig_ip.next
       #log.debug('Packet In Handeling: TCP_Packet: %s', orig_tcp)
       #return
       if isinstance(orig_tcp, pkt.udp):
        #log.debug('Packet In Handling: TCP Packet: %s', orig_tcp)
        rtp_payload = orig_tcp.payload
        #log.debug(".......................................................payload%s", rtp_payload)
        if len(rtp_payload) >= 12:  # Minimum RTP header length is 12 bytes
            if (rtp_payload[0] >> 6) & 0x03 == 2:  # Check RTP version (2 for valid RTP packet)
                #log.debug('Packet In Handling: RTP Packet')
                # Extract RTP header fields
                version = (rtp_payload[0] >> 6) & 0x03
                sequence_number = rtp_payload[2:4]
                timestamp = rtp_payload[4:8]
                payload_type = rtp_payload[1] & 0x7F
                # Extract RTP payload
                rtp_payload_data = rtp_payload[12:]  # Assuming 12-byte RTP header length
                #log.debug('RTP Version: %s, Sequence Number: %s, Timestamp: %s, Payload Type: %s', version, sequence_number, timestamp, payload_type)
                pass
            else:
                #log.debug('Not a valid RTP packet')
                pass
        else:
            #log.debug('Packet payload length is insufficient for RTP')
            pass
       else:
        #log.debug('Not a TCP packet')
        pass
    else:
        #log.debug('Not an IP packet')
        pass
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    #avodi broadcast from LLDP
    if packet.effective_ethertype == packet.LLDP_TYPE:
      #log.debug("LLDP broadcast, so the drop fuction is called")
      return drop()
      
    if packet.type >= 34525:
       #log.debug("packet type is 34525, so the drop fuction is called")
       return drop() 
            
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@      
    ip_pck = packet.find(pkt.ipv4)
    if ip_pck is None or not ip_pck.parsed:
       #log.error("No IP packet in IP_TYPE packet")
       return 
    if ip_pck.protocol == 253 or ip_pck.dstip == IPAddr("224.0.0.255"):
       ####################log.debug("Packet is not ours, give packet back to monitoring manager")
       return
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 
    #log.debug("packet in check")
    packet = event.parsed
    port = event.port                                                  #To pass
    S = str(packet.src)
    h_s = S[16]
    ####log.debug('h_s = S[16] -- > %s', h_s)
    host_s = Host_Dictionary [str(h_s)]
    ####log.debug("host_s = Host_Dictionary [int(h_s)] is --> %s", host_s)
    ####log.debug('The host ip is %s', Host_IP[host_s])
    D = str(packet.dst)
    h_d = D[16]
    #log.debug('h_d = D[16] -- > %s', h_d)
    host_d = Host_Dictionary [str(h_d)]
    #log.debug("host_d = Host_Dictionary [int(h_d)] is --> %s", host_d)
    src_switch = mac_map[str(packet.src)][0]
    ####log.debug('src_switch: %s', src_switch)
    #----------------------------------------------------------------
    
    
    path = _get_raw_path (mac_map[str(packet.src)][0], mac_map[str(packet.dst)][0])
    if path != None:
      try: 
        path_port = _get_path (path, mac_map[str(packet.src)][0], mac_map[str(packet.dst)][0], mac_map[str(packet.src)][1], mac_map[str(packet.dst)][1])
         
        #log.debug("path_port %s", path_port) 
        match = ofp_match_withHash.from_packet(packet)                                            #@@@
        #log.debug('Packet IN Matching fields: %s',match)
        #
        
        #log.debug("New flow to monitor %s", str(match.__hash__()))                               #@@@
	
        self._install(match,packet.src, packet.dst, path_port, path)                              # 11
        i = path_port[0]
        #all_ports = of.OFPP_FLOOD
        msg = of.ofp_packet_out(data = event.ofp)
        #msg.actions.append(of.ofp_action_output(port = all_ports))
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        #self.connection.send(msg)         
        msg.actions.append(of.ofp_action_output(port = int(i[2])))
        core.openflow.getConnection(int(i[0])).send(msg)
        #log.debug("packet_out to avoid drop the first packet # %s", SUM )
        SUM += 1
      except: 
         log.debug("Error happened when path instaled")
         return

    else:
        log.debug("The path not install, so packet Drop, the path none")
        return 
      
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@  
                                
        
    path_port_tuple = tuple(path_port)  
    if path_port_tuple not in monitored_paths:
            #monitored_paths[path_port_tuple] = set([match])
            x = match.__hash__()
            monitored_paths[x] = path_port_tuple
            monitored_paths2[x] = path                                          # adding the computed path to the dictionary
            pair = [host_s, host_d]
            #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            def enqueue_request():
                  #log.debug("Enqueuing request for x----> %s", x)
                  request_queue.put((port, host_s, host_d, src_switch, packet, path, x))  # Store all parameters in the queue
            #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
            if len(Traffic_pairs) == 0:
               Traffic_pairs[x] = pair
               #log.debug("The Traffic pairs dictionary is updated, first time.")
               #scheduler = sched.scheduler(time.time, time.sleep)
               #scheduler.enter(20, 1, self.Collect, (port, host_s, host_d, src_switch, packet, path, x))
               #t2 = threading.Thread(target = scheduler.run)
               #t2.start()
               #%%%%%%%%%%%%%%%%%%%%%%%%%
               #def enqueue_request():
                  #log.debug("Enqueuing request for x-----------------------------------------------------> %s", x)
                  #request_queue.put((port, host_s, host_d, src_switch, packet, path, x))  # Store all parameters in the queue
    
               #scheduler.enter(2, 1, enqueue_request, ())
               t = threading.Thread(target= enqueue_request)
               t.start()
               #%%%%%%%%%%%%%%%%%%%%%%%%

            #ch = pair in Traffic_pairs.values()
            ch = x in Traffic_pairs.keys()
            if ch == False:
               Traffic_pairs[x] = pair
               #log.debug("The Traffic pairs dictionary is updated.")
               #scheduler = sched.scheduler(time.time, time.sleep)
               #scheduler.enter(20, 1, self.Collect, (port, host_s, host_d, src_switch, packet, path, x))
               #t2 = threading.Thread(target = scheduler.run)
               #t2.start()
               t = threading.Thread(target= enqueue_request)
               t.start()
            #log.debug("The Traffic pairs dictionary is %s", Traffic_pairs)
            #log.debug("switch_port_monitored_paths dictionary is %s", monitored_paths)
            #log.debug("The row_monitored_paths dictionary is %s", monitored_paths2)
            
            #%%%%%%%%%%%%%%%%%%%%%%%%%
            #def enqueue_request():
                #log.debug("Enqueuing request for x-----------------------------------------------------> %s", x)
                #request_queue.put((port, host_s, host_d, src_switch, packet, path, x))  # Store all parameters in the queue
    
            #scheduler.enter(2, 1, enqueue_request, ())
            
      
      #%%%%%%%%%%%%%%%%%%%%%%%%
               
            #Indicator = False
            ##for i in Traffic_pairs.values():
            #for i in Traffic_pairs.keys():
                ##if set (pair) == set (i):
                #if x == i:
                   #log.debug ('The pair already seen --> %s', pair)
                   #Indicator = True
                   
            #if Indicator == False and len(Traffic_pairs) != 0:    
            #if len(Traffic_pairs) != 0: 
              #scheduler = sched.scheduler(time.time, time.sleep)
              #scheduler.enter(2, 1, self.Collect, (port, host_s, host_d, src_switch, packet, path, x))
              #t2 = threading.Thread(target = scheduler.run)
              #t2.start()
            #---------------------------------------------------------------------------------------------------
            #monitored_paths[match.__hash__()] = (path_port_tuple)
            #monitored_paths2[match.__hash__()] = path  # adding the computed path to the dictionary
            #log.debug("1==================================monitored_paths %s", monitored_paths)
    else:
            monitored_paths[path_port_tuple].add(match)
            monitored_paths2[path].add(match)
            
    self.raiseEvent(NewFlowEntry(path_port, match, packet.src, packet.dst, mac_map[str(packet.src)][0], mac_map[str(packet.dst)][0], src_ip, dst_ip, path))   
    #log.debug('Packet in function is completed ...................... ')
    #scheduler = sched.scheduler(time.time, time.sleep)
    #self.Collect(port, host_s, host_d, src_switch, packet, path)         
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ 
      

  #-----------------------------------------------------------------------


      
  # disconect event
  def disconnect (self):                                                                               # 5 
    if self.connection is not None:
      self.connection.removeListeners(self._listeners)
      #log.debug("Disconnect %s" % (self.connection,))
      self.connection = None
      self._listeners = None


  # connect event, to connect to the switch in the handshaking stage
  def connect (self, connection):                                                                      # 4
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()                                                                                  # 5
    #log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()


  def _handle_ConnectionDown (self, event):
    self.disconnect() 
#------------------------------------------------------
#-------------------------------------------
# Does not used
class NewSwitch(Event):
	def __init__(self, switch):
		Event.__init__(self)
		self.switch = switch  
#------------------------------------------------------
#------------------------------------------------------
	
class l2_multi (EventMixin):                                                                           #@ Discover of topology                 #1
  _core_name = "DCN9"                                                                                  #@ we want to be core.DNC6 *##############################################*
  _eventMixin_events = set([NewSwitch,])                                                               # adding a new event *##############################################*
  global Links_weight_Dictionary
  global G
  global path_port
  
  
  def __init__ (self):
     def startup ():
      core.openflow.addListeners(self ,priority=0)
      core.openflow_discovery.addListeners(self)
     core.call_when_ready(startup, ('openflow','openflow_discovery'))
     log.debug("core.OpenFlow is listening")                                                        #@@@@@@@@@@
     log.debug("DCN9 started")                                                                      #@@@@@@@@@@

  def _handle_ConnectionUp (self, event):  
                                                                                # 2
      global nodes
      global switches_info
      sw = switches.get(event.dpid)
      nodes.append(event) 
      switches_info[int(event.dpid)] = {}
      if sw is None:   
        sw = Switch()
        switches[event.dpid] = sw
        sw.connect(event.connection)
        myswitches.append(event.dpid)
        my_switches[event.dpid]= event.connection
        #log.debug ("  my_switches: %s",  my_switches )
      else:
        sw.connect(event.connection)
      self.raiseEvent(NewSwitch(sw))
        
  # Does not used      
  def pairwise(self, iterable):
         a, b = tee(iterable)
         next(b, None)
         return izip(a, b)


  # Does not used
  def Check(self, Pair, List_of_pairs = [], *args):
        Flag = False
        for x in List_of_pairs:
            if set (x) == set (Pair):
               Flag = True
               break
        return Flag


  def _handle_LinkEvent(self, event):                                                                                        # 6
        #log.debug("Link Event handeling from %s to %s." % (event.link.dpid1, event.link.dpid2))
        
        def flip (link):
            log.debug("Hello, I am flip function")
            return Discovery.Link(link[2],link[3], link[0],link[1])
            
            
        global util_val
        global G, current_p, CC
        global Links_ports
        global Links_weight_Dictionary
        global Links_utilization
        global clear_do
        
        
        l = event.link 
        sw1 = l.dpid1 
        sw2 = l.dpid2 
        pt1 = l.port1 
        pt2 = l.port2 
        Links_ports [l.dpid1, l.port1] = [l.dpid1,l.dpid2]
        Links_ports [l.dpid2, l.port2] = [l.dpid2,l.dpid1]
        G.add_node( sw1 ) 
        G.add_node( sw2 ) 
        no_edges = 0
        for p in myswitches:
          for q in myswitches:
             if adjacency[p][q]!= None: 
               no_edges += 1
        if event.added:
            if adjacency[sw1][sw2] is None:
              adjacency[sw1][sw2] = l.port1
              adjacency[sw2][sw1] = l.port2 
              G.add_edge(sw1,sw2)
              G.add_edge(sw2,sw1)
              G[sw1][sw2]["weight"] = 700                                                           # initial weight(Cost) = 500
              G[sw2][sw1]["weight"] = 700
              G[sw1][sw2]["Utilization"] = 0                                                 # list??????????????????????????????????????
              G[sw2][sw1]["Utilization"] = 0
              Links_utilization[(sw1, sw2)] = 0
              Links_utilization[(sw2, sw1)] = 0
              #log.debug("weight of the graph: %s",list(G.edges().items()))
              #log.debug("link %s ------ %s is added", sw1, sw2)
              #G[sw1][sw2]['weight'] = Links_weight_Dictionary
            if ori_adjacency[sw1][sw2] is None:
              ori_adjacency[sw1][sw2] = l.port1
              ori_adjacency[sw2][sw1] = l.port2  
        if event.removed:
            try:
                if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
                G.remove_edge(sw1,sw2)
                #log.debug("link %s ------ %s is removed", sw1, sw2)
                #if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]
                #log.debug("link %s ------ %s is removed", sw2, sw1)
                #G.remove_edge(sw2,sw1)
            except:
                log.debug("Remove edge error")
        try: 
             N= netx.number_of_nodes(G)
             #log.debug("number of the nodes in the graph: %s",N)
             E= netx.number_of_edges(G)
             #log.debug("number of the edges in the graph: %s",E)
             if (N == 20) and (E == 64) and CC == 0:
                 log.debug("... The Network Graph is complete now ...")
                 log.debug("Graph nodes are: %s",G.nodes())
                 log.debug("Graph edges are: %s",G.edges())
                 clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                 if clear_do == 0:
                    for sw in switches.values():
                        #print('sw',sw)
                        if sw.connection is None: continue
                        sw.connection.send(clear)
                        #log.debug('Hello, I am Clear Opject, all rules in %s are deleted',sw)
                        clear_do = 1
                 else:
                    log.debug('The switches already clear')
                 CC = CC + 1
             else:
                 #log.debug('*** The Network Graph is incomplete at the moment ***')
                 pass
        except: 
               log.debug('*** An Error happened in ((_handle_LinkEvent)) ***')

#-------------------------------------------         
def launch (spam = True, __INSTANCE__ = None):
  #f=open('/home/ali/pox/ext/DCN.txt', 'r')
  f=open('/home/mohammed/pox-halosaur/ext/optimization/PQ/DCN.txt', 'r')
  line=f.readline()
  #print ('line',line)
  while line:
    a=line.split()
    mac_map[a[0]]=( int(a[1]),  int(a[2]))
    line=f.readline()
  f.close()
  log.debug('MAC addresses map is: %s', mac_map)
  core.registerNew(l2_multi)
  core.openflow.addListenerByName("PortStatsReceived", _handle_portstats_received)
  Timer(2,_send_timer, recurring=True)  # timer set to execute every one second
  
