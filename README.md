# scappy built on scapy.

this is just a simple scappy class that is built on top of the scapy package.

this aims at simplifying the use of scappy in a way.

you need root permissions to use this package though.


*this includes various classes*

**packet**

**send**


# packet

```python

from scappy import packet

p = packet(hostnames, ports) or p = packet(hostList, portList)

p.hostList

# returns a set of the host or the host lists altogether

p.hostList = hostname or hostList

# sets the host of the packet

p.portList

# does the same thing as the hostList


# this methods return the layer or protocols that are in the OSI stack.

**p.ether**

**p.ip**

**p.tcp**

**p.udp**

**p.icmp**

**p.payload**

# payload is a message like "GET / HTTP1.1 \r\n\n"

pkt = p(ip, tcp, payload=None)

# calling p returns the crafted packet for your use.

# pass the layers in the order in which you want them in the packet.

pkt

# is actually an object that contains the packet and not the packet itself.

# so this means you set other properties of the packet before sending it.

# There are mostly used properties predefined for your use.

pkt.ttl(24)

pkt.src(localhost)

# can be used to spoof an ip address by setting a false source address

pkt.sport(330)

# sets the source port

pkt.syn_flag()

packt = pkt() || pkt.pkt

# use either of this two methods to get the raw packet.


# in case you know any parameters that you want to add the parameter stack of any of the protocols.

# just get the name of the protocols and the add the parameter to it.

pkt.IP_params.tty = (1, 24)

pkt.TCP_params.dport = (440, 443)

# aside calling the packet layer and passing the protocols to create a custom layer

pkt = p.layer2packet / layer3packet / icmp2packet / icmp3packet


```

:+1:

:sparkles:

**thank you**

*\(c\)Danny Mcwaves*




