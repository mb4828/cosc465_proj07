from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ipv4 import ipv4,tcp
from pox.lib.addresses import IPAddr,EthAddr
import pox.openflow.libopenflow_01 as of


class p7(object):
    def __init__ (self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        # yippee.  a switch connected to us.
        log.info("Got connection from {}".format(event.connection))

    def _handle_PacketIn (self, event):
        inport = event.port         # input port number on which packet arrived at switch
        packet = event.parsed       # reference to POX packet object
        pktin = event.ofp           # reference to Openflow PacketIn message (ofp_packet_in)

        if not packet.parsed:
            log.warning("{} {} ignoring unparsed packet".format(dpid, inport))
            return

        # packet is a "normal" POX packet object
        log.debug("GOT A NEW PACKET")
        tcphdr = packet.find('tcp')

        if tcphdr is None:
            # for any non-TCP traffic, flood out all ports
            log.debug("packet is non-TCP traffic")
            pktout = of.ofp_packet_out(data = pktin, 
                                    actions = of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(pktout.pack())

        else: 
            # for any TCP traffic, install Openflow rules
            if ( (packet.srcip != IPAddr('10.0.0.4') and packet.dstip != IPAddr('10.0.0.4')) 
                    or inport==5 ):
                # packet is not suspicious or is from middlebox
                # send directly to intended destination
                log.debug("packet is TCP traffic, but it is safe")
                outport = int(str(packet.dstip)[-1])
                log.debug("outport = {}".format(outport))

                actions = [ of.ofp_action_output(port = outport) ]
                flowmod = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                    idle_timeout=10,
                                    hard_timeout=10,
                                    buffer_id=event.ofp.buffer_id,
                                    match=of.ofp_match.from_packet(packet, inport),
                                    actions=actions)
            
            else:
                # packet is suspicious; forward to middlebox
                log.debug("packet is suspicious; forward to middlebox")
                actions = [ ofp_action_dl_addr.set_dst(EthAddr('00:00:00:00:00:05')),
                            of.ofp_action_output(port=5) ]
                flowmod = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                    idle_timeout=10,
                                    hard_timeout=10,
                                    buffer_id=event.ofp.buffer_id,
                                    match=of.ofp_match.from_packet(packet, inport),
                                    actions=actions)
            
            event.connection.send(flowmod.pack())

def launch():
    core.registerNew(p7)
