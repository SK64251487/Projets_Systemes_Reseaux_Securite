#!/usr/bin/env python3
"""
Minimal Mininet Topology for Zero Trust SDN
Creates a network with 2 hosts, 1 web server, 1 remediation server and 1 OpenFlow switch
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
import time

def create_zero_trust_topology():
    """Create minimal topology for Zero Trust testing"""
    
    info("*** Creating Zero Trust SDN Topology\n")
    
    # Create network
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    info("*** Adding controller\n")
    # Connect to Ryu controller
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )
    
    info("*** Adding switch\n")
    # Add OpenFlow 1.3 switch
    s1 = net.addSwitch(
        's1',
        protocols='OpenFlow13',
        failMode='secure'
    )
    
    info("*** Adding hosts\n")
    # Host 1: Client host
    h1 = net.addHost(
        'h1',
        ip='10.0.0.1/24',
        mac='00:00:00:00:00:01'
    )
    
    # Host 2: Client host
    h2 = net.addHost(
        'h2',
        ip='10.0.0.2/24',
        mac='00:00:00:00:00:02'
    )
    
    # Web Server
    web_server = net.addHost(
        'web',
        ip='10.0.0.10/24',
        mac='00:00:00:00:00:10'
    )
    
    # Remediation Server
    rserver = net.addHost(
        'rserver',
        ip='10.0.0.20/24',
        mac='00:00:00:00:00:20'
    )
    
    info("*** Creating links\n")
    # Connect hosts to switch with bandwidth limits
    net.addLink(h1, s1, bw=100)              # 100 Mbps
    net.addLink(h2, s1, bw=100)              # 100 Mbps
    net.addLink(web_server, s1, bw=1000)     # 1 Gbps
    net.addLink(rserver, s1, bw=1000)  # 1 Gbps
    
    info("*** Starting network\n")
    net.start()
    
    info("*** Waiting for controller connection\n")
    time.sleep(5)
    
    info("*** Testing connectivity\n")
    dumpNodeConnections(net.hosts)
    
    info("\n*** Network Information:\n")
    info(f"Host 1:              {h1.IP()} - {h1.MAC()}\n")
    info(f"Host 2:              {h2.IP()} - {h2.MAC()}\n")
    info(f"Web Server:          {web_server.IP()} - {web_server.MAC()}\n")
    info(f"Remediation Server:  {rserver.IP()} - {rserver.MAC()}\n")
    
    # Start web server
    info("\n*** Starting Web Server\n")
    web_server.cmd('python3 -m http.server 80 &')
    
    # Start remediation server (simple HTTP server on port 8080)
    info("*** Starting Remediation Server\n")
    rserver.cmd('python3 -m http.server 8080 &')
    
    return net, h1, h2, web_server, rserver, s1

def run_basic_tests(net, h1, h2, web_server, rserver):
    """Run basic connectivity tests"""
    info("\n*** Running basic connectivity tests\n")
    
    # Test ping between hosts
    info("Testing h1 -> h2: ")
    result = h1.cmd(f'ping -c 3 -W 1 {h2.IP()}')
    info("OK\n" if "0% packet loss" in result else "FAILED\n")
    
    info("Testing h1 -> web server: ")
    result = h1.cmd(f'ping -c 3 -W 1 {web_server.IP()}')
    info("OK\n" if "0% packet loss" in result else "FAILED\n")
    
    info("Testing h1 -> remediation server: ")
    result = h1.cmd(f'ping -c 3 -W 1 {rserver.IP()}')
    info("OK\n" if "0% packet loss" in result else "FAILED\n")
    
    info("Testing h2 -> web server: ")
    result = h2.cmd(f'ping -c 3 -W 1 {web_server.IP()}')
    info("OK\n" if "0% packet loss" in result else "FAILED\n")

def main(): 
    """Main function"""
    setLogLevel('info')
    
    # Create topology
    net, h1, h2, web_server, rserver, s1 = create_zero_trust_topology()
    
    # Run basic tests
    run_basic_tests(net, h1, h2, web_server, rserver)
    
    info("\n*** Network ready for Zero Trust testing\n")
    info("*** Hosts: 'h1', 'h2'\n")
    info("*** Servers: 'web' (port 80), 'rserver' (port 8080)\n")
    info("*** Use 'exit' to stop the network\n\n")
    
    # Start CLI
    CLI(net)
    
    # Cleanup
    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    main()
