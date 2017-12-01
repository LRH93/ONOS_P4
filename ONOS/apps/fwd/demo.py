#echo"sudo ln /usr/bin/ovs-controller /usr/bin/controller"
# coding=utf8
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import dumpNodeConnections

import argparse
from time import sleep



class MyTopo( Topo ):

    def __init__( self ):

        # initilaize topology 
        Topo.__init__( self )

        # add hosts and switches
        h1 = self.addHost( 'h1',ip="172.168.1.1/24",mac="00:04:00:00:00:0A",privateDirs=[ '~/h1' ])
        h2 = self.addHost( 'h2',ip="172.168.1.8/24",mac="00:04:00:00:00:0B",privateDirs=[ '~/h2' ])
        h3 = self.addHost( 'h3',ip="172.168.1.5/24",mac="00:04:00:00:00:0C",privateDirs=[ '~/h3' ])

        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )

        # add links
        self.addLink(h1,switch1,1,1)
        self.addLink(switch1,h3,2,1)
        self.addLink(switch1,switch2,3,1)
        self.addLink(switch2,h2,2,1)
        #self.addLink(h1,h3,2,2)


#sudo mn --custom first.py --topo mytopo
#topos = { 'mytopo': ( lambda: MyTopo() ) }
#ip link delete s1-eth1 type veth


"""
h1 xterm
https://github.com/mininet/mininet/wiki/Introduction-to-Mininet

http://mininet.org/api/annotated.html

Host Configuration Methods

Mininet hosts provide a number of convenience methods for network configuration:

    IP(): Return IP address of a host or specific interface.
    MAC(): Return MAC address of a host or specific interface.
    setARP(): Add a static ARP entry to a host's ARP cache.
    setIP(): Set the IP address for a host or specific interface.
    setMAC(): Set the MAC address for a host or specific interface
"""

def main():
    print "_____liuruohan_____"
    net = Mininet(topo = MyTopo())
    net.start()

    print "\n"
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    """
    #首先根据名字从网络中获取主机
    h1 = net.get("h1")
    #对获取的主机执行命令
    h1.setIP("192.168.0.99",intf="%s-eth1"%h1.name)
    h1.setMAC("00:04:00:00:00:FF",intf="%s-eth1"%h1.name)
    h1.cmd("wireshark")
    """
    s1=net.get("s1")
    s1.setIP("172.168.1.2",intf="%s-eth1"%s1.name)
    s1.setIP("172.168.1.3",intf="%s-eth2"%s1.name)
    s1.setIP("172.168.1.4",intf="%s-eth3"%s1.name)

    s2=net.get("s2")
    s2.setIP("172.168.1.6",intf="%s-eth1"%s2.name)
    s2.setIP("172.168.1.7",intf="%s-eth2"%s2.name)

    """
    num_hosts=2
    for n in xrange(num_hosts):
        h = net.get('h%d' % (n + 1))
        print h.setIP("192.168.0.%d"%(n+1),intf="%s-eth2"%h.name)
        print "\n"+h.name
        #h.cmd("ifconfig %s-eth2 211.71.67.%d netmask 255.255.255.0"%( h.name, (n+1) ) )
        #print h.cmd("ifconfig")
        print "privateDirs="+str(h.privateDirs)
        #h.cmd("wireshark")
    """


    print "Initial Configuration"
    print net.hosts  

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()

