from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI

def clearIP(host):
    for intf in host.intfList():
        host.cmd('ifconfig %s 0.0.0.0' % intf)

class LoopTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        b1 = self.addHost('b1')
        b2 = self.addHost('b2')
        b3 = self.addHost('b3')

        self.addLink(h1, b1, bw=10)
        self.addLink(h2, b2, bw=10)

        self.addLink(b1, b2, bw=10)
        self.addLink(b2, b3, bw=10)
        self.addLink(b3, b1, bw=10)

if __name__ == '__main__':
    topo = LoopTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.start()

    h1, h2, b1, b2, b3 = net.get('h1', 'h2', 'b1', 'b2', 'b3')

    h1.cmd('ifconfig h1-eth0 10.0.0.1/8')
    h2.cmd('ifconfig h2-eth0 10.0.0.2/8')

    clearIP(b1)
    clearIP(b2)
    clearIP(b3)

    for n in [h1, h2, b1, b2, b3]:
        n.cmd('./scripts/disable_offloading.sh')
        n.cmd('./scripts/disable_ipv6.sh')

    CLI(net)
    net.stop()