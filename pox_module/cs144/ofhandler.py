# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
import pox.lib.packet.icmp as icmp
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns
from pox.lib.addresses import IPAddr, EthAddr


import time
import code
import os
import struct
import sys

log = core.getLogger()
FLOOD_DELAY = 5
IPCONFIG_FILE = '/home/ubuntu/cs144_lab3/IP_CONFIG'
IP_SETTING={}
RTABLE = []
ROUTER_IP={}

INTERNAL_IP = {}
INTERNAL_IP['10.0.1.10'] = 'server1'
INTERNAL_IP['10.0.1.12'] = 'server2'
INTERNAL_IP['10.0.1.13'] = 'sw0-eth1'
INTERNAL_IP['10.0.1.14'] = 'sw0-eth2'
INTERNAL_IP['10.0.1.11'] = 'sw0-eth3'


INTERNAL_NAME = {}
NAME_SETTING = {}
#Topology is fixed 
#sw0-eth1:server1-eth0 sw0-eth2:server2-eth0 sw0-eth3:Internet

class RouterInfo(Event):
  '''Event to raise upon the information about an openflow router is ready'''

  def __init__(self, info, rtable):
    Event.__init__(self)
    self.info = info
    self.rtable = rtable


class OFHandler (EventMixin):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent
    self.sw_info = {}
    self.connection.send(of.ofp_switch_config(miss_send_len = 20000))
    for port in connection.features.ports:
        intf_name = port.name.split('-')
        if(len(intf_name) < 2):
          continue
        else:
          intf_name = intf_name[1]
        if intf_name in ROUTER_IP.keys():
          self.sw_info[intf_name] = (ROUTER_IP[intf_name], port.hw_addr.toStr(), '10Gbps', port.port_no)
    self.rtable = RTABLE
    # We want to hear Openflow PacketIn messages, so we listen
    self.listenTo(connection)
    self.listenTo(core.cs144_srhandler)
    core.cs144_ofhandler.raiseEvent(RouterInfo(self.sw_info, self.rtable))

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    pkt = event.parse()
    #code.interact(local=locals())
        
    #log.debug("OFHandler: Got OF PacketIN!\n")

    if( event.port == 3 and pkt.type == ethernet.ARP_TYPE and pkt.next.opcode == arp.REQUEST):
        arp_req = pkt.next
        #log.debug("\nGot a packet request from port 3, flood it\n")
        arp_reply = arp()
        arp_reply.hwtype = arp_req.hwtype
        arp_reply.prototype = arp_req.prototype
        arp_reply.hwlen = arp_req.hwlen
        arp_reply.protolen = arp_req.protolen
        arp_reply.opcode = arp.REPLY
        arp_reply.protodst = arp_req.protosrc
        arp_reply.protosrc = arp_req.protodst
        arp_reply.hwsrc = EthAddr(self.sw_info["eth3"][1])
        arp_reply.hwdst = arp_req.hwsrc
        e = ethernet(type=pkt.type, src=arp_reply.hwsrc, dst=arp_req.hwsrc)
        e.payload = arp_reply
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)
    elif (event.port == 3) :
        #log.debug("OFHandler: raise SRPacketIn event\n")
        #log.debug("OFHandler: packet from outside, translate address\n")
        #implement an internal NAT here
        packet = event.parse()
        #print 'original packet: ', packet 
        if( packet.type == ethernet.IP_TYPE ):
          ip_pkt = packet.next
          #print INTERNAL_IP.keys()
          #print IP_SETTING.values()
          #print ip_pkt.dstip 
          dst_ip = ip_pkt.dstip.toStr()
          src_ip = ip_pkt.srcip.toStr()
          if(dst_ip in INTERNAL_IP.keys()):
            #print "change IP destination\n"
            ip_pkt.dstip = IPAddr(IP_SETTING[INTERNAL_IP[dst_ip]])
            ip_pkt.csum = ip_pkt.checksum()
#            ip_pkt.raw = ip_pkt.pack()
            ip_pkt.raw = None
            packet.next = ip_pkt
        elif( packet.type == ethernet.ARP_TYPE ):
          if( packet.next.opcode == arp.REPLY ):
            arp_reply = packet.next
            dst_ip = arp_reply.protodst.toStr()
            if( dst_ip in INTERNAL_IP.keys()):
              #print "change arp reply dst \n"
              arp_reply.protodst = IPAddr(IP_SETTING[INTERNAL_IP[dst_ip]])
              #print arp_reply.protodst
              arp_reply.raw = None
              packet.next = arp_reply
        #print "modified packet: ", packet
        raw_packet = packet.pack()
        core.cs144_ofhandler.raiseEvent(SRPacketIn(raw_packet, event.port))
    else:
        raw_packet = pkt.raw
        core.cs144_ofhandler.raiseEvent(SRPacketIn(raw_packet, event.port))
        # Drop this packet as we won't reference it.  Just trying to be
        # safe so that OVS's/vswitchd's buffer doesn't have stale packets.
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

  def _handle_SRPacketOut(self, event):
    msg = of.ofp_packet_out()
    new_packet = event.pkt
    if(event.port == 3):
      #out going packet, need to go through NAT
      packet = ethernet(raw = event.pkt)
      if( packet.type == ethernet.IP_TYPE ):
        #print "in SRPacketOut"
        #print packet
        ip_pkt = ipv4(raw=event.pkt[ethernet.MIN_LEN:])
        if( ip_pkt.protocol == ipv4.UDP_PROTOCOL and ip_pkt.next.dstport == 53):
          src_ip = ip_pkt.srcip.toStr()
          if( src_ip in IP_SETTING.values()):
            ip_pkt.srcip = IPAddr(INTERNAL_NAME[NAME_SETTING[src_ip]])
            ip_pkt.csum = ip_pkt.checksum()
            packet.next = ip_pkt
            #new_packet = packet.pack()
            #event.pkt[ethernet.MIN_LEN:ipv4.hl] = ip_pkt.tyhdr()
            #ipp = ip_pkt
            #event.pkt[ethernet.MIN_LEN:ip_pkt.hl] = struct.pack('!BBHHHBBHII', (ipp.v << 4) + ipp.hl, ipp.tos, ipp.iplen, ipp.id, (ipp.flags << 13) | ipp.frag, ipp.ttl, ipp.protocol, ipp.csum, ipp.srcip.toUnsigned(), ipp.dstip.toUnsigned())
            #npkt = ipv4(raw=event.pkt[ethernet.MIN_LEN:])
            #print npkt
#            udp_pkt= ip_pkt.next
#            dns_pkt = udp_pkt.next
#            print dns_pkt
#            d = dns()
#            u = udp()
#            ipp = ipv4()
#            ipp.protocol = ipp.UDP_PROTOCOL
#            ipp.srcip = IPAddr(INTERNAL_NAME[NAME_SETTING[src_ip]])
#            ipp.dstip = ip_pkt.dstip
#            e = ethernet()
#            e.src = packet.src
#            e.dst = packet.dst
#            e.type = e.IP_TYPE
#            ipp.payload = udp_pkt
#            e.payload = ipp
#            new_packet = e.pack()
        else:  
          src_ip = ip_pkt.srcip.toStr()
          #print ip_pkt.srcip
          if(src_ip in IP_SETTING.values()):
#            print "change IP src\n"
            ip_pkt.srcip = IPAddr(INTERNAL_NAME[NAME_SETTING[src_ip]])
#            print ip_pkt.srcip
            ip_pkt.csum = ip_pkt.checksum()
            ip_pkt.raw = None
            packet.next = ip_pkt
            if ( ip_pkt.protocol == ipv4.ICMP_PROTOCOL ):
                icmp_pkt = ip_pkt.next
                icmp_pkt.raw = None
                if( icmp_pkt.type == 3 ):
                        ip_hdr = icmp_pkt.next.next
                        ip_hdr.dstip = IPAddr(INTERNAL_NAME[NAME_SETTING[src_ip]])
                        #print "Replace icmp MSG IP addr !!!!\n"
                        #print icmp_pkt
            new_packet = packet.pack()
      elif( packet.type == ethernet.ARP_TYPE ):
        if( packet.next.opcode == arp.REQUEST ):
#          print "get a arp request"
          arp_req = packet.next
          src_ip = arp_req.protosrc.toStr()
          if( src_ip in IP_SETTING.values()):
#            print "change arp request src \n"
            arp_req.protosrc = IPAddr(INTERNAL_NAME[NAME_SETTING[src_ip]])
#            print arp_req.protosrc
            arp_req.raw = None
            packet.next = arp_req
            new_packet = packet.pack()
    msg.actions.append(of.ofp_action_output(port=event.port))
    msg.buffer_id = -1
    msg.in_port = of.OFPP_NONE
    msg.data = new_packet
    #log.debug("SRServer catch SRPacketOut event, fwd_pkt=%r, port=%s\n" % (event.pkt, event.port))
    self.connection.send(msg)

class SRPacketIn(Event):
  '''Event to raise upon a receive a packet_in from openflow'''

  def __init__(self, packet, port):
    Event.__init__(self)
    self.pkt = packet
    self.port = port

class cs144_ofhandler (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  _eventMixin_events = set([SRPacketIn, RouterInfo])

  def __init__ (self, transparent):
    EventMixin.__init__(self)
    self.listenTo(core.openflow)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    OFHandler(event.connection, self.transparent)



def get_ip_setting():
  if (not os.path.isfile(IPCONFIG_FILE)):
    return -1
  f = open(IPCONFIG_FILE, 'r')
  for line in f:
    if(len(line.split()) == 0):
      break
    name, ip = line.split()
    if ip == "<ELASTIC_IP>":
      log.info("ip configuration is not set, please put your Elastic IP addresses into %s" % IPCONFIG_FILE)
      sys.exit(2)
    #print name, ip
    IP_SETTING[name] = ip
    NAME_SETTING[ip] = name

  RTABLE.append( ('0.0.0.0', '10.0.1.1', '0.0.0.0', 'eth3') )
  RTABLE.append( ('%s' % IP_SETTING['server1'], '%s' % IP_SETTING['server1'], '255.255.255.255', 'eth1') )
  RTABLE.append( ('%s' % IP_SETTING['server2'], '%s' % IP_SETTING['server2'], '255.255.255.255', 'eth2') )

# We don't want to flood immediately when a switch connects.
  ROUTER_IP['eth1'] = '%s' % IP_SETTING['sw0-eth1']
  ROUTER_IP['eth2'] = '%s' % IP_SETTING['sw0-eth2']
  ROUTER_IP['eth3'] = '%s' % IP_SETTING['sw0-eth3']

  for key in INTERNAL_IP.keys():
    value = INTERNAL_IP[key]
    INTERNAL_NAME[value] = key


  return 0

def launch (transparent=False):
  """
  Starts an cs144 - L2 learning switch.
  """    
  core.registerNew(cs144_ofhandler, str_to_bool(transparent))
  
  r = get_ip_setting()
  if r == -1:
    log.debug("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
    sys.exit(2)
    #sys.exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
  else:
    log.debug('*** ofhandler: Successfully loaded ip settings for hosts\n %s\n' % IP_SETTING)
