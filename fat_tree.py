import fnss
import subprocess
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import Link, TCLink, Intf
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.node import OVSController, DefaultController, Host, OVSKernelSwitch, OVSSwitch
from fnss.netconfig.delays import clear_delays
import time
import random
import math
from datetime import datetime
import subprocess
now = datetime.now()
def create_datacenter_topology():
    # Create FNSS topology
    fnss_topo = fnss.fat_tree_topology(k=4)

    # Clear all types of delays
    clear_delays(fnss_topo)

    # Set link attributes
    fnss.set_capacities_constant(fnss_topo, 10, 'Mbps')
    fnss.set_buffer_sizes_constant(fnss_topo, 1000, 'packets')

    # Convert FNSS topology to Mininet
    mn_topo = fnss.to_mininet(fnss_topo, relabel_nodes=True)

    # Create a Mininet instance and start it
    net = Mininet(controller=RemoteController)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net = Mininet(topo=mn_topo, link=TCLink, switch=OVSSwitch, autoSetMacs=True, autoStaticArp=True, controller=c0)
    net.start()
    time.sleep(5)
    
#===============================================


    def generate_exponential_udp_traffic():
        h1 = net.get('h1')
        h16 = net.get('h16')
        h16.cmd('iperf -s -u &')  # Start iperf server in UDP mode

        total_time = 60  # Total time for the traffic generation (in seconds)
        initial_volume = "1M"  # Initial volume to transfer

        # Generate exponential distribution parameters
        mean_interval = 10  # Mean interval between updates (seconds)
        lambda_param = 1.0 / mean_interval

        current_time = 0
        while current_time < total_time:
            # Generate an interval from exponential distribution
            interval = random.expovariate(lambda_param)
        
            # Update the traffic volume
            current_volume = int(initial_volume[:-1]) + int((current_time / total_time) * 10)  # we can modify it as we like
            current_volume_str = str(current_volume) + "M"
            print(f"Time elapsed: {current_time:.2f}s - Current volume: {current_volume_str}")

            # Update the iperf command for h1
            cmd = 'iperf -c {} -t {} -i 1 -u -n {}'.format(h16.IP(), interval, current_volume_str)
            h1.cmd(cmd)

            current_time += interval
            time.sleep(interval)

        # Wait for iperf traffic to finish
        h1.wait()

    # Call the function to start generating exponential UDP iperf traffic between h1 and h16
    #generate_exponential_udp_traffic()




#================================================    
    # Start iperf traffic
    def generate_iperf_traffic():
        h16 = net.get('h16') 
        h14 = net.get('h14') 
        h16.cmd('iperf -s _u &')  # Start iperf server in UDP mode
        h14.cmd('iperf -s -u &')  # Start iperf server in UDP mode
        procs = []
        hosts = [net.get('h1'),net.get('h3')#,net.get('h3'),net.get('h4') ,net.get('h5'),net.get('h6'),net.get('h7'),net.get('h8')#,net.get('h9'),net.get('h10'),     net.get('h11'),net.get('h12')

]
        cmd1 = 'iperf -c {} -t 60 -i 1 -n 20M -u &'.format(h16.IP())  # Use UDP mode
        proc = net.get('h1').popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        procs.append(proc)
        #time.sleep(20)  # Wait for 5 seconds between flows
        #cmd2 = 'iperf -c {} -t 60 -i 1 -n 100M -u &'.format(h14.IP())  # Use UDP mode
        #proc = net.get('h3').popen(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #procs.append(proc)
        #for i, host in enumerate(hosts):
            #cmd = 'iperf -c {} -t 60 -i 1 -n 100M -u &'.format(h16.IP())  # Use UDP mode
            #proc = host.popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #procs.append(proc)

            #if i < len(hosts) - 1:
               #time.sleep(10)  # Wait for 5 seconds between flows

        # Wait for iperf traffic to finish
        for proc in procs:
            proc.wait()
        
    #generate_iperf_traffic()  
    
    sender1 = net.get('h1')
    sender2 = net.get('h2')
    sender3 = net.get('h3')
    sender4 = net.get('h4')

    receiver1 = net.get('h16')
    receiver2 = net.get('h15')
    receiver3 = net.get('h14')
    receiver4 = net.get('h13') 
        
    # Generate traffic function
    def generate_DITG_raffic():
        sender1 = net.get('h1')
        sender2 = net.get('h2')
        sender3 = net.get('h3')
        sender4 = net.get('h4')
        sender5 = net.get('h5')
        sender6 = net.get('h6')
        sender7 = net.get('h7')
        sender13 = net.get('h13')
  
        receiver1 = net.get('h16')
        receiver2 = net.get('h15')
        receiver3 = net.get('h14')
        receiver4 = net.get('h13')
        receiver5 = net.get('h12')

        # Start receiver processes
        receiver1.cmd('./ITGRecv &')
        receiver2.cmd('./ITGRecv &')
        receiver3.cmd('./ITGRecv &')
        receiver4.cmd('./ITGRecv &')
        receiver5.cmd('./ITGRecv &')
        
        
        def start_vlc_stream(sender_host, receiver_host, video_path):
            
        
            sender_cmd = "sudo -su mohammed cvlc 1.mp4 --sout '#rtp{proto = rtp, mux = ts, dst=10.0.0.16, port=5004}' &"
            sender_host.cmd(sender_cmd)
            print("the stream is ran")

        def start_vlc_receiver(receiver_host):
            # Start VLC receiver on the receiver_host
        
            receiver_cmd = "sudo -su mohammed vlc rtp://@10.0.0.16:5004 &"
            receiver_host.cmd(receiver_cmd)
            print("the receiver is ran")
          

        
        
        
       
        
        
        
        
        
        
        
        # Start VLC streaming from h1 to h2
        video_path = "1.mp4"  # Replace with actual video path
        #Start VLC receiver on h3
        start_vlc_receiver(receiver1)
        time.sleep(3)
        start_vlc_stream(sender5, receiver1, video_path)
        time.sleep(10)
        
       
        
        
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the fourth traffic is sending")
        time.sleep(10)
        
       
        
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the fifth traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the seventh traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the eighth traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the ninth traffic is sending")
        time.sleep(10)
        #sender2.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        #print("the tenth traffic is sending")
        #time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the eleventh traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the twelveth traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the threteinth traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 120  -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the forteinth traffic is sending")
        time.sleep(10)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 1500 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the fifteinth traffic is sending")
        time.sleep(5)
        sender6.cmd('./ITGSend -T ICMP -a {}  -c 1500 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver5.IP()))
        print("the seventh traffic is sending")
        time.sleep(5)
        
        sender13.cmd('./ITGSend -T ICMP -a {}  -c 512 -t 1200000 -B V 10 100 W 10 100 &'.format(receiver2.IP()))
        print("the fifth traffic is sending ==========================")
        time.sleep(10)
        
    generate_DITG_raffic()
    
    
    
    
    
    
    
    # Start CLI
    CLI(net)

    # Stop Mininet
    net.stop()

if __name__ == '__main__':
    create_datacenter_topology()

