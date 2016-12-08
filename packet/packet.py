"""
this is just a simple module for manipulating the hostname(s) that passed to check the network
it belong to.
"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import ICMP, IP, Ether, TCP, UDP


class packet:
    """
        all the methods and variables found in here are somehow related to the
    """

    __eth = Ether
    __ip = IP
    __icmp = ICMP
    __tcp = TCP
    __udp = UDP

    def __init__(self, host, port):
        self.__host = host
        self.__ports = port
        self.__hostList = host if isinstance(host, list) else [host]
        self.__portList = port if isinstance(port, list) else port if isinstance(port, tuple) else [port]

    @property
    def hostList(self):
        return self.__hostList

    @hostList.setter
    def hostList(self, other):
        if isinstance(other, list):
            self.__hostList.extend(other)
        else:
            self.__hostList.append(other)

    @property
    def portList(self):
        return self.__portList

    @portList.setter
    def portList(self, other):
        if isinstance(other, list):
            self.__portList.extend(other)
        else:
            self.__portList.append(other)

    @property
    def ether(self):
        return Ether()

    @property
    def ip(self):
        if len(self.hostList) == 1:
            return IP(dst=self.__hostList[0])
        else:
            return IP(dst=self.__hostList)

    @property
    def tcp(self):
        if len(self.portList) == 1:
            return TCP(dport=self.__portList[0])
        else:
            return TCP(dport=self.__portList)

    @property
    def udp(self):
        if len(self.portList) == 1:
            return UDP(dport=self.__portList[0])
        else:
            return UDP(dport=self.__portList)

    @property
    def icmp(self):
        return ICMP(type=8)

    @property
    def payload(self, message):
        return message

    def __call__(self, *args, **kwargs):
        """
        call is supposed to take a specific set of parameters.
        the parameters must correspond to the names of the layers in the packet and in that order.
        :param args: a tuple of the arguments.
        :param kwargs: any keyword arguments. this is specially for the payload
        :return: the packet construction
        """
        sep, *rest = args
        proto = {
            "ip": self.ip,
            "icmp": self.icmp,
            "tcp": self.tcp,
            "udp": self.udp,
            "ether": self.ether
        }

        packt = proto[sep]
        for i in rest:
            i = i.lower()
            packt /= proto[i]

        try:
            packt /= kwargs["payload"]
        except KeyError:
            pass

        return props(packt)

    def layer2packet(self, payload=None):
        return self.__call__("ether", "ip", "tcp", payload=payload) if payload is not None \
            else self.__call__("ether", "ip", "tcp")

    def layer3packet(self, payload=None):
        return self.__call__("ip", "tcp", payload=payload) if payload is not None \
            else self.__call__("ip", "tcp")

    def icmp2packet(self, payload=None):
        return self.__call__("ether", "ip", "icmp", payload=payload) if payload is not None \
            else self.__call__("ether", "ip", "icmp")

    def icmp3packet(self, payload=None):
        return self.__call__("ip", "icmp", payload=payload) if payload is not None \
            else self.__call__("ip", "icmp")


class props:
    """
    this are some of the properties of the packets that are going to be added later to the packet after creation.
    """
    def __init__(self, pakt):
        self.pkt = pakt

    def syn_flag(self):
        self.pkt["TCP"].flags = "S"

    def ack_flag(self):
        self.pkt["TCP"].flags = "A"

    def src(self, src):
        self.pkt["IP"].src = src

    def sport(self, sport):
        self.pkt["TCP"].sport = sport

    def ttl(self, ttl):
        self.pkt["IP"].ttl = ttl
        
    @property
    def IP_params(self):
        return self.pkt["IP"]

    @property
    def TCP_params(self):
        return self.pkt["TCP"]

    @property
    def UDP_params(self):
        return self.pkt["UDP"]

    @property
    def ICMP_params(self):
        return self.pkt["ICMP"]

    @property
    def ETHER_params(self):
        return self.pkt["Ether"]

    def __str__(self):
        return str(self.pkt)

    def __call__(self, *args, **kwargs):
        return self.pkt


if __name__ == '__main__':
    from pprint import pprint
    pkt = packet("mcbook", 80)
    pprint(pkt("ip", "tcp", "icmp", payload="GET / HTTP1.0\n\n").pkt)
    pprint(pkt.layer2packet(payload="xxxxxxxxxxxx").pkt)
    pct = pkt("ip", "tcp")
    pct.ttl(64)
    pct.sport(444)
    pct.src("localhost")
    pct.TCP_params.flags = "A"
    pprint(pct.pkt)
