
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
import pox.lib.util as util
from pox.lib.recoco import Timer
from itertools import tee
from .DCN9 import ofp_match_withHash
from datetime import datetime
from collections import defaultdict
from collections import namedtuple
import pox.lib.packet as pkt
import struct
from pox.lib.addresses import IPAddr,EthAddr
import time
import threading
from .DCN9 import monitored_paths
from .DCN9 import monitored_paths2
from .DCN9 import Traffic_type
from .DCN9 import Traffic_pairs
from .DCN9 import Host_IP
from .DCN9 import Links_utilization
from .DCN9 import G
from .DCN9 import my_switches
from .DCN9 import adjacency
from .DCN9 import status_dict
from .disjoint_paths import edge_disjoint_shortest_pair
#from optimization.PQ.DCN7 import status_dict
from .DCN9 import _install_monitoring_path
import sched
#import datetime
from .DCN9 import _get_raw_path
#from .DCN9 import proactive_path_installation
from .DCN9 import proactive
#--------------------------
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
import pox.openflow.nicira as nx
import networkx as netx
#--------------------------
con1 = False
# Create a lock for synchronization
query_lock = threading.Lock()
log = core.getLogger()
#my_switches= {}
switches = {}
Payload = namedtuple('Payload', 'match dst timeSent')

mac_map = {} 
src_dst_packets = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
packet_loss_dict = defaultdict(lambda: defaultdict(int))
packet_source_counters = {}
packet_destination_counters = {}
packet_counters_dict={}
query_flag = {}
packet_loss_dict = {}
#------------------------------------------------------------------------>
m = { 'h1' : ("00:00:00:00:00:01") , 'h2': ("00:00:00:00:00:02"), 'h3' : ("00:00:00:00:00:03") , 'h4' : ("00:00:00:00:00:04"), 'h5' : ("00:00:00:00:00:05"), 'h6' : ("00:00:00:00:00:06"), 'h7' : ("00:00:00:00:00:07"), 'h8' : ("00:00:00:00:00:08"), 'h9' : ("00:00:00:00:00:09"), 'h10' : ("00:00:00:00:00:0a"), 'h11' : ("00:00:00:00:00:0b"), 'h12' : ("00:00:00:00:00:0c"), 'h13' : ("00:00:00:00:00:0d"), 'h14' : ("00:00:00:00:00:0e"), 'h15' : ("00:00:00:00:00:0f"), 'h16' : ("00:00:00:00:00:10")}
ma = { 'h1' : 1 , 'h2': 2, 'h3' : 3 , 'h4' : 4, 'h5' :5, 'h6' : 6, 'h7' : 7, 'h8' : 8, 'h9' : 9, 'h10' : 10, 'h11' : 11, 'h12' : 12, 'h13' : 13, 'h14' : 14, 'h15' : 15, 'h16' : 16}
#------------------------------------------------------------------------>
class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.go()
     
    def _run(self):
        t1 = threading.Thread(target = self._run1())
        t1.start()

    def _run1(self):
        self.is_running = False
        self.go()
        self.function(*self.args, **self.kwargs)

    def go(self):
        if not self.is_running:
            self._timer = threading.Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False
#------------------------------------------------------------------------>
def delay_timer_mon ():
    global status_dict
    global Traffic_pairs
    global status_dict
    paths_tuples = dict(monitored_paths)
    #log.debug("paths_tuples are :%s",paths_tuples)
    paths = dict (monitored_paths2)  
    #log.debug("paths:%s",paths)                                                 # Create a copy of the monitored_paths dictionary
    #log.debug("Monitoring paths as touples %s", paths_tuples)
    log.debug("We are in the delay_timer_mon ()")
    #log.debug ('Traffic_type is: %s',Traffic_type)
    log.debug("Monitoring paths at %s", str(datetime.now()))
    #log.debug("monitored_paths are: %s", monitored_paths)
    log.debug("monitored_paths2 are: %s", monitored_paths2)
    log.debug("flows_delay_status %s", status_dict)
    log.debug("Traffic_type %s",Traffic_type)
    #log.debug("link utilization: %s", Links_utilization)
    status_dict_copy = dict(status_dict)  # Create a copy of the dictionary
    #for path_hash, delay in status_dict.items():
    for path_hash, delay in status_dict_copy.items():
    
        hash_id = path_hash
        try:
           RTP_delay = delay[3]
        except:
           log.debug("the delay not calculate, yet")
           pass
        
        
        try: 
           if RTP_delay > 70 and hash_id in paths: 
              if Traffic_type[hash_id]  == "RTP":                                          #our initilal condition to replace the path that suffers from delay
               log.debug (">>>>>>>>>>>>>>>>>>>>>>>> >>>>>>>>>>>>>>>>>>>>>>>>---------------------------------- <<<<<<<<<<<<<<<<<<<<<<<<<< <<<<<<<<<<<<<<<<<<<<<<<<<<")
               log.debug (">>>>>>>>>>>>>>>>>>>>>>>> >>>>>>>>>>>>>>>>>>>>>>>> the RTP flow suffering from delay <<<<<<<<<<<<<<<<<<<<<<<<<< <<<<<<<<<<<<<<<<<<<<<<<<<<")
               log.debug (">>>>>>>>>>>>>>>>>>>>>>>> >>>>>>>>>>>>>>>>>>>>>>>>---------------------------------- <<<<<<<<<<<<<<<<<<<<<<<<<< <<<<<<<<<<<<<<<<<<<<<<<<<<")
               log.debug ('Traffic_type is: %s',Traffic_type)
               log.debug("path hash is: %s", path_hash)
               log.debug("path delay is: %s", delay[3])
               log.debug ("The path that suffers from delay is: %s", paths[hash_id])
               log.debug ("The host pairs of the path are : %s", Traffic_pairs[hash_id])
               #if Traffic_type[hash_id] in Traffic_type:
               #log.debug("This path carries traffic of class %s", Traffic_type[hash_id])
               src = paths[hash_id][0]
               dst = paths[hash_id][-1]
           
               selected_path = _get_raw_path (src, dst)
               log.debug(" active paths are: %s", monitored_paths2)
           
           
           
               #all_paths = netx.all_simple_paths(G, source=src, target=dst, cutoff=9)
               # Convert generator to a list and sort paths by length in ascending order
               #all_sorted_paths = sorted(list(all_paths), key=lambda x: len(x))
               #log.debug("all_sorted_paths are  %s", all_sorted_paths)
               #log.debug("new path  %s", selected_path)
               #log.debug(" active paths are: %s", monitored_paths2)
               # Create a list of path values from your dictionary
               #path_values = list(paths.values())
               #selected_path = all_sorted_paths[-1]
               #log.debug("Selecting an unmatching path:%s", selected_path)
           
               my_proactive = proactive()
               my_proactive.proactive_path_installation ( selected_path, Traffic_pairs[hash_id])
           
           
           else:
               log.debug("the path: %s is not suffering  from delay",path_hash)
              
        except:
               #log.debug("there is not such hash in the  Traffic_type--------------------------------------------------------->>>>>: %s",path_hash)
               pass
                          
           
             #for i in dis_joint:
               #if i != monitored_paths2[hash_id]:
                  #log.debug("The potential disjoint path is  %s", i)
                  #monitored_paths2[hash_id] = i                                        #update the path in dictionary as well
                  #proactive_path_installation (i, Traffic_pairs[hash_id] )
                  #break

#------------------------------------------------------------------------->
def pairwise1(iterable):
         a, b = tee(iterable)
         next(b, None)
         return zip(a, b)
#-------------------------------------------------------------------------> 

    
    
#------------------------------------------------------------------------->   
#-------------------------------------------------------------------------> 
def _handle_portstats_received(event):
            #log.debug("portstats_received %s",event.connection.dpid )
            dpid = event.connection.dpid 
            #paths_copy = dict(monitored_paths)
            for stat in event.stats:
                                                                 
            #log.debug("Monitoring paths %s", paths_copy)
            #log.debug("flows_delay_status %s", status_dict)
               #for i_d, path in paths_copy.items():
                  
                  #L = len(path) 
                  #for i in path:
                      #sw = i[0] 
                      #if sw == dpid:
                         port_number = stat.port_no
                         #if port_number == i[1]:
                         rx_dropped = stat.rx_dropped
                         #if port_number == i[2]:
                         tx_dropped = stat.tx_dropped
                         rx_over_err = stat.rx_over_err
                         tx_errors = stat.tx_errors
                         #log.debug("tx_dropped: %s, rx_dropped %s, tx_errors: %s, rx_over_err %s" %(tx_dropped, rx_dropped,tx_errors,rx_over_err)) 
                         packet_loss_dict.setdefault(dpid, {})[port_number] = (tx_dropped, rx_dropped)

                         #packet_loss_dict[dpid][port_number] = (tx_dropped,rx_dropped)
            #log.debug("packet_loss_dict %s",packet_loss_dict)


#scheduler = sched.scheduler(time.time, time.sleep)
#scheduler1 = sched.scheduler(time.time, time.sleep)
#scheduler2 = sched.scheduler(time.time, time.sleep)

def _timer_MonitorPaths():
        scheduler = sched.scheduler(time.time, time.sleep)

        def MeasureDelay():
            #log.debug("Monitoring paths delay %s", str(datetime.now()))
            #if not path_port:                                                                   # Check if the list is empty
               #log.debug("path_port is empty")
               #return  # Return from the function                                             # Walk through all distinct paths
          
            paths_copy = dict(monitored_paths)  
            paths_copy2 = dict (monitored_paths2)                                                # Create a copy of the monitored_paths dictionary 
            ######################log.debug("Monitoring paths %s", paths_copy)
            ##########################3log.debug("Monitoring paths2 %s", paths_copy2)
            #log.debug("flows_delay_status %s", status_dict)
            #log.debug("flows_clases_state %s",Traffic_type)
            #log.debug("link utilization: %s", Links_utilization)
            for i_d, path in paths_copy.items():
             #log.debug('key_path: %s', i_d)
             
             
              p = path[0]
              p_src = path[0]
              #log.debug("=================p_src: %s", p_src)
              p_dst = path[-1]
                
              #log.debug("p_dst: %s", p_dst)
              
              ###ip_pck = pkt.ipv4(protocol = 253, srcip = IPAddr(src_ip) ,dstip = IPAddr(dst_ip))
              ip_pck = pkt.ipv4(protocol = 253, srcip = IPAddr(i_d) ,dstip = IPAddr("224.0.0.255"))						
              #log.debug("path %s", p)
              #log.debug("IP_Packet for experimntal testing %s", ip_pck)
              #log.debug("------------------------- %s", IPAddr(match))
              #pl = Payload(dst,id(p_src), time.time())   
              ###pl = Payload(match, dst, time.time())                                               # data including time to measure the time delay
              pl = Payload(i_d, p_dst[0], time.time()) 
              #log.debug("Payload %s", pl)
              ip_pck.set_payload(str(pl).encode()) 		
              eth_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE)                             # use something that does not interfer with regular traffic
              #log.debug("path-source %s", p_src) 
              eth_packet.src = struct.pack("!Q", p_src[0])[2:]                                    # convert dpid to EthAddr
              #log.debug("path-ethernet source %s", eth_packet.src) 
              eth_packet.dst = struct.pack("!Q", p_dst[0])[2:]
              eth_packet.set_payload(ip_pck)
              #log.debug("path-ethernet source %s", eth_packet.dst) 
              msg = of.ofp_packet_out()
              #log.debug("OF MSG %s", msg) 
              msg.actions.append(of.ofp_action_output(port = int(p[2])))
              #log.debug("OF actions %s", msg.actions) 
              for action in msg.actions:
                    if isinstance(action, of.ofp_action_output):
                        #log.debug("Output action port: %s", action.port) 
                        pass
              msg.data = eth_packet.pack()
              #log.debug("OF MSG data %s", msg.data) 
              #switches[p_src].connection.send(msg)
              core.openflow.getConnection(int(p[0])).send(msg)
				
              #eth_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE)                          
              #eth_packet.src = struct.pack("!Q", p_src)[2:]
              #eth_packet.dst = struct.pack("!Q", p_src)[2:]
              #eth_packet.set_payload(ip_pck)
              #msg = of.ofp_packet_out()
              #msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
              #msg.data = eth_packet.pack()				
              #switches[p_src].connection.send(msg)
              #core.openflow.getConnection(int(i[0])).send(msg)
              #####log.debug (" the measurement delay packet sent from %s to %s" %(p_src[0],p_dst[0]))

              # Reschedule the task after 2 seconds
            #scheduler.enter(5, 1, MeasureDelay, ())
            ######################################################log.debug("flows_delay_status %s", status_dict)
            #log.debug("link utilization: %s", Links_utilization)
            ##############################################log.debug("weight of the graph: %s",list(G.edges().items()))
            scheduler.enter(1, 1, MeasureDelay)

              

        
             
     
      # Create a thread and start it
      #try:
         #measure_thread = threading.Thread(target=MeasureDelay, args=(p_src, p_dst, path_port, src_ip, dst_ip))
         #measure_thread.start()	
      							
             
      #except:
          #log.debug("error happen (MeasureDelay)") 
      #try:								
          #MeasureDelay(p_src, p_dst, path_port)     
      #except:
          #log.debug("list index out of range")                
      
        
        def processing_delay ():
            log.debug("Monitoring switches processing delay %s", str(datetime.now()))
            #if not path_port:                                                                   # Check if the list is empty
               #log.debug("path_port is empty")
               #return  # Return from the function                                             # Walk through all distinct paths
          
            paths_copy = dict(switches)                                                  # Create a copy of the monitored_paths dictionary 
            #log.debug("Monitoring paths %s", paths_copy)
            #log.debug("flows_delay_status %s", status_dict)
            for i_d, sw in paths_copy.items():
              #log.debug('key_path: %s', i_d)
             
             
              #p = path[0]
              #p_src = path[0]
              #log.debug("=================p_src: %s", p_src)
              #p_dst = path[-1]
                
              #log.debug("p: %s", p)
              
              ###ip_pck = pkt.ipv4(protocol = 253, srcip = IPAddr(src_ip) ,dstip = IPAddr(dst_ip))
              ip_pck = pkt.ipv4(protocol = 254, srcip = IPAddr(i_d) ,dstip = IPAddr("224.0.0.255"))						
              #log.debug("path %s", p)
              #log.debug("IP_Packet for experimntal testing %s", ip_pck)
              #log.debug("------------------------- %s", IPAddr(match))
              #pl = Payload(dst,id(p_src), time.time())   
              ###pl = Payload(match, dst, time.time())                                               # data including time to measure the time delay
              pl = Payload(i_d, i_d, time.time()) 
              #log.debug("Payload %s", pl)
              ip_pck.set_payload(str(pl).encode()) 		
              eth_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE)                             # use something that does not interfer with regular traffic
              #log.debug("path-source %s", p_src) 
              eth_packet.src = struct.pack("!Q", i_d)[2:]                                    # convert dpid to EthAddr
              #log.debug("path-ethernet source %s", eth_packet.src) 
              eth_packet.dst = struct.pack("!Q", i_d)[2:]
              eth_packet.set_payload(ip_pck)
              #eth_packet = pkt.ethernet(type=pkt.ethernet.IP_TYPE)                          #!!!
              #eth_packet.src = struct.pack("!Q", p_src)[2:]
              #eth_packet.dst = struct.pack("!Q", p_src)[2:]
              #eth_packet.set_payload(ip_pck)
              msg = of.ofp_packet_out()
              msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
              msg.data = eth_packet.pack()				
              #switches[p_src].connection.send(msg)
              #try:
              core.openflow.getConnection(int(i_d)).send(msg)
              #except:
                 #log.debug("out of range")
				
            scheduler.enter(5, 1, processing_delay)
                
            
        def start_scheduler():
            measure_thread = threading.Thread(target=scheduler.run)
            measure_thread.start()
        # Schedule the functions
        scheduler.enter(1, 1, MeasureDelay)
        #scheduler.enter(5, 1, processing_delay)
       

        

        # Start the scheduler
        start_scheduler()

                 
  	
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


class Monitoring (object):
		
        def __init__ (self,postfix):
	
             #log.debug("Monitoring coming up")
            
		
             def startup():
			
                       core.openflow.addListeners(self, priority=0xfffffffe)               # took 1 priority lower as the discovery module, although it should not matter
                       core.DCN9.addListeners(self)                                        
                       self.f1 = open("Paths-delay.%s.csv"%postfix, "w")
                       self.f1.write("Measurement type,Time,Source MAC,Destination MAC,Event Source,Event Destination,Match-ID,Traffic Type,Traffic src and dst,path,Delay\n")
                       self.f1.flush()
                       
                       self.f2 = open("Switches-delay.%s.csv"%postfix, "w")
                       self.f2.write("Measurement type, Time, Switch DPID, Delay\n")
                       self.f2.flush()
                       
                       self.experiment = postfix	
                       log.debug("Monitoring started")
	
             core.call_when_ready(startup, ('DCN9'))                                       # Wait for data center power optimization model to be started
		
        def __del__(self):
            self.f.close()
       
        
        def _handle_NewSwitch (self, event):                                  
             switch = event.switch
             #log.debug("New switch to Monitor %s", switch.connection)
             #switches[switch.connection.dpid] = switch
             #log.debug("switches dictionary %s",switches)
             switch.addListeners(self)
             #self.connection = switch.connection  # Store the switch connection in the 'connection' attribute
             switches[switch.connection.dpid] = switch
             #log.debug("switches dictionary %s",switches)
             #my_switches[event.dpid]= event.connection
             #log.debug ("  my_switches: %s",  my_switches )
             
             
        
		
        def _handle_NewFlowEntry(self, event):
                global con1  
                #log.debug("con1: %s", con1)                     
                match = event.match 
                #log.debug("New flow handeling")
                #log.debug("handle new flow-match %s", match)
                #log.debug("remove flow event hash %s", str(match.__hash__()))
                path = event.path_port	
                #log.debug("path %s", path)
                src_mac = event.src_mac
                #log.debug("src_mac %s", src_mac)
                dst_mac = event.dst_mac
                #log.debug("dst_mac %s", dst_mac)
                if match.__hash__() in monitored_paths:
                   #log.debug("3==================the monitoring flow-path is: %s" , monitored_paths[match.__hash__()])
                   status_dict[match.__hash__()] = []
                   path = event.path_port	
                   #log.debug("path %s", path)
                   src_mac = event.src_mac
                   #log.debug("src_mac %s", src_mac)
                   dst_mac = event.dst_mac
                   #log.debug("dst_mac %s", dst_mac)
                   sw_src = event.sw_src
                   sw_dst = event.sw_dst
                   src_ip = event.src_ip
                   dst_ip = event.dst_ip
                   #match = ofp_match_withHash.from_ofp_match_Superclass(event.ofp.match)
                   #print("match =======================================",match)
                   #print("path_port =======================================",self.path_port)
                   #print("sw_src =======================================",sw_src)
                   #print("sw_dst =======================================",sw_dst)
                   #print("src_mac =======================================",src_mac)
                   #print("dst_mac =======================================",dst_mac)
                   #print("src_ip =======================================",src_ip)
                   #print("dst_ip =======================================",dst_ip)
                   #print("path =======================================",path)
      
               
                   _install_monitoring_path(self,sw_src, sw_dst , path, src_ip, dst_ip, match.__hash__() )
                   if con1  ==  False:
                      #log.debug ("monitor paths fuction have called")
                      _timer_MonitorPaths()
                      con1 = True
                     
                   #if path not in monitored_paths:
                   #monitored_paths[path] = set([match])
                   #log.debug("4------------------monitored_paths %s", monitored_paths)
                   #log.debug("4------------------status_dict %s", status_dict)		
					
                #else:
                     #monitored_paths[path].add(match)
                     #log.debug("monitored_paths %s", monitored_paths)
			
				
                #monitored_pathsByMatch[match] = path
                #log.debug("monitored_pathsByMatch %s", monitored_pathsByMatch)
	
	
	#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  
        def _handle_FlowRemoved(self, event):                                               
            match = ofp_match_withHash.from_ofp_match_Superclass(event.ofp.match)
            #log.debug("remove flow event: %s", match) 
            #log.debug("remove flow event hash %s", str(match.__hash__()))
            #packet = event.parsed
            #match = ofp_match_withHash.from_packet(packet)
            #log.debug("remove flow event: %s", match) 
            # Remove the corresponding key from monitored_paths
            if match.__hash__() in monitored_paths:
                del monitored_paths[match.__hash__()]
                del monitored_paths2[match.__hash__()]
                #log.debug("monitored_paths2: event to delete: %s", match.__hash__())
                try:
                   del status_dict[match.__hash__()]
                   #log.debug("status_dict: event to delete: %s", match.__hash__())
                except:
                   #log.debug("status_dict: there is no such event to delete: %s", match.__hash__())
                   pass
                del Traffic_pairs[match.__hash__()]
                try:
                   del Traffic_type[match.__hash__()]
                   #log.debug("Traffic_type: event to delete: %s", match.__hash__())
                except:
                   #log.debug("Traffic_type: there is no such event to delete: %s", match.__hash__())
                   pass
                #####log.debug("Removed flow from monitored_paths: %s", match.__hash__())
            # Remove the corresponding key from monitored_paths
            #if match.__hash__() in status_dict:
                #del status_dict[match.__hash__()]
                #####log.debug("Removed flow from status_dict: %s", match.__hash__())
                #log.debug('tatus_dict: %s', status_dict)
                try:
                    del packet_counters_dict[match.__hash__()]
                    #log.debug("Removed flow from packet_counters_dict: %s", match.__hash__())
                except:
                    #log.debug("packet_loss_dict: there is no such event to delete")
                    pass
                try:    
                    del packet_loss_dict[match.__hash__()]
                    #log.debug("Removed flow from packet_loss_dict: %s", match.__hash__())
                except:
                    #log.debug("packet_loss_dict: there is no such event to delete")
                    pass
                
             
  	
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
       
                         
                  
            
        def _handle_PacketIn(self, event):
	
                #log.debug("Incoming packet")
                timeRecv = time.time()
                packet = event.parsed
		
                if packet.effective_ethertype != pkt.ethernet.IP_TYPE:
                    return
			
                ip_pck = packet.find(pkt.ipv4)
		
                if ip_pck is None or not ip_pck.parsed:
                    #log.error("No IP packet in IP_TYPE packet")
                    return EventHalt
		
                #if ip_pck.protocol != 253: #or ip_pck.dstip != IPAddr("224.0.0.255"):
                    #log.debug("Packet is not ours, give packet back to regular packet manager")
                    #return
                if ip_pck.protocol == 254:
                    #log.debug("the processing delay message have been Receiving, with payload %s."%(ip_pck.payload))
                    payload = eval(ip_pck.payload)
                    # Retrieve the switch DPID
                    switch_dpid = event.connection.dpid
                    #log.debug("switch_dpid %s."%(switch_dpid))
                    switch_connection = event.connection
                    
                    if payload.dst == switch_dpid:
                       #log.debug("Delay from switch %s to %s = %f, flow maching: %s"%(EthAddr(packet.src), EthAddr(packet.dst), timeRecv - payload.timeSent, payload.match))
                       # Extract the TTL value from the IP packet header
                       ttl = ip_pck.ttl
                       #log.debug("TTL value: %d" % ttl)
                       #log.debug("Received packet from switch %s" % switch_connection)
                       #log.debug("Received packet from switch %s" % switch_dpid)
                       timeRecv = time.time()
                       current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                       #log.debug("processing delay of switch %s is %s" %(switch_dpid,(timeRecv - payload.timeSent)*1000))
                       self.f2.write("switch congestion-ID,%s,%s,%f\n" % (current_time,   switch_dpid,  (timeRecv - payload.timeSent)*1000 ))
                       self.f1.flush()
                       # Update the global dictionary with the new information
                       #if payload.match in status_dict:
                          #status_dict[payload.match] = [current_time, str(EthAddr(packet.src)), str(EthAddr(packet.dst)), timeRecv - payload.timeSent]
                          #self.f1.write("Path based flow match-ID,%s,%s,%s,%s,%s,%s,%f\n" % (current_time, EthAddr(packet.src), EthAddr(packet.dst),payload.dst, switch_dpid, payload.match, (timeRecv - payload.timeSent)*1000 ))
                          #self.f1.flush()
                       #else:
                          #log.debug("the path-matchID already have deleted from the list:%s", payload.match )
                          #pass

                       #log.debug('network state: %s', (status_dict))
                
                if ip_pck.protocol == 253:
                    #log.debug("Received monitoring packet, with payload %s."%(ip_pck.payload))
                    payload = eval(ip_pck.payload)
                    # Retrieve the switch DPID
                    switch_dpid = event.connection.dpid
                    #log.debug("switch_dpid %s."%(switch_dpid))
                    switch_connection = event.connection
                    
                    if payload.dst == switch_dpid:
                       #log.debug("Delay from switch %s to %s = %f, flow maching: %s"%(EthAddr(packet.src), EthAddr(packet.dst), timeRecv - payload.timeSent, payload.match))
                       # Extract the TTL value from the IP packet header
                       ttl = ip_pck.ttl
                       #log.debug("TTL value: %d" % ttl)
                       #log.debug("Received packet from switch %s" % switch_connection)
                       #log.debug("Received packet from switch %s" % switch_dpid)
                       current_time = datetime.now().strftime("%H:%M:%S")
                       
                       # Update the global dictionary with the new information
                       if payload.match in status_dict:
                          status_dict[payload.match] = [current_time, str(EthAddr(packet.src)), str(EthAddr(packet.dst)), (timeRecv - payload.timeSent)*1000]
                          #status_dict[payload.match] = [current_time, mac_map[str(EthAddr(packet.src))][0], mac_map[str(EthAddr(packet.dst))][0], (timeRecv - payload.timeSent)*1000]
                          #self.f1.write("Path based flow match-ID,%s,%s,%s,%s,%s,%s,%f\n" % (current_time, EthAddr(packet.src), EthAddr(packet.dst),payload.dst, switch_dpid, payload.match, Traffic_type[payload.match], (timeRecv - payload.timeSent)*1000))
                          if payload.match in Traffic_type:
                             traffic_type_value = Traffic_type[payload.match]
                          else:
                             traffic_type_value = "none"
                             
                          if payload.match in Traffic_pairs:
                             traffic_pairs_value = Traffic_pairs[payload.match]
                             traffic_pairs_value = ' '.join(map(str, traffic_pairs_value))
                          else:
                             traffic_pairs_value = "none"
                            
                             
                          if payload.match in monitored_paths2:
                             monitored_paths2_value = monitored_paths2[payload.match]
                             monitored_paths2_value = ' '.join(map(str, monitored_paths2_value))
                          else:
                             monitored_paths2_value = "none"
                          
                          self.f1.write("Path based flow match-ID,%s,%s,%s,%s,%s,%s,%s,%s,%s,%f\n" % (current_time, EthAddr(packet.src), EthAddr(packet.dst), payload.dst, switch_dpid, payload.match, traffic_type_value, traffic_pairs_value, monitored_paths2_value, (timeRecv - payload.timeSent) * 1000))
                          #self.f1.write("Path based flow match-ID,%s,%s,%s,%s,%s,%s,%f\n" % (current_time, mac_map[str(packet.src)][0], mac_map[str(packet.dst)][0],payload.dst, switch_dpid, payload.match, (timeRecv - payload.timeSent)*1000))
                          self.f1.flush()
                       else:
                          #log.debug("the path-matchID already have deleted from the list:%s", payload.match )
                          pass

                       #log.debug('network state: %s', (status_dict))
                else:
                   #log.debug ('_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_None of the related packets+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_')  
                   pass  
						
def launch (postfix=datetime.now().strftime("%Y%m%d%H%M%S")):
	
        """
        Starts the component
        """
        core.registerNew(Monitoring, postfix)
        #f=open('/home/ali/pox/ext/DCN.txt', 'r')
        f=open('/home/mohammed/pox-halosaur/ext/optimization/PQ/DCN.txt', 'r')
        line=f.readline()
        #print ('line',line)
        while line:
              a=line.split()
              mac_map[a[0]]=( int(a[1]),  int(a[2]))
              line=f.readline()
        f.close()
        #log.debug('MAC addresses map is: %s', mac_map)
        RepeatedTimer(5, delay_timer_mon,)
        #core.openflow.addListenerByName("PortStatsReceived", _handle_portstats_received)
	


