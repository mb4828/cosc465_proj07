#!/usr/bin/env python

'''
Middlebox traffic manipulator and logger for Project 7.
'''

import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import ipv4,tcp
from pox.lib.addresses import EthAddr,IPAddr
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger
import time

class Middlebox(object):
    def __init__(self, net):
        self.net = net
        self.clog = open('contentlog.txt','w')
        self.acont = dict()                         # key "srcip:srcport:dstip:dstport"

    def main(self):    
        while True:
            try:
                dev,ts,pkt = self.net.recv_packet(timeout=1.0)
            except SrpyNoPackets:
                continue
            except SrpyShutdown:
                break

            # only deal with tcp packets; ignore everything else
            tcphdr = pkt.find('tcp')
            if tcphdr is not None:
                log_info("Got packet for TCP source: {}".format(pkt.dump()))
                pktkey = self.getkey(pkt)

                # log packet data in application content dictionary
                log_info("Packet data: {}".format(tcphdr.payload))
                if pktkey not in self.acont.keys():
                    self.acont[pktkey] = tcphdr.payload
                else:
                    self.acont[pktkey] += tcphdr.payload

                # remove all instances of "NSA" and replace with "Fluffy Bunnies"
                # also check for instances of panda
                data = tcphdr.payload.split(" ")
                kill = 0; changed = 0
                for i in range(len(data)):
                    if "NSA" in data[i]:
                        log_info("Instance of 'NSA' detected")
                        changed = 1
                        j = data[i].find("NSA")
                        data[i] = data[i][0:j] + "Fluffy Bunnies" + data[i][j+3:len(data[i])]
                    if "panda" in data[i]:
                        log_info("Red alert! Instance of 'panda' detected!")
                        kill = 1
                        tcphdr.RST = 1
                        tcphdr.set_payload('')
                        tcphdr.tcplen = 20
                        break

                # rebuild tcp payload and set tcplen
                if not kill and changed:
                    newdata = ""
                    datalen = len(data)
                    for i in range(datalen-1):
                        newdata += data[i] + " "
                    newdata += data[-1]

                    log_info("Content is now harmless: {}".format(newdata))
                    tcphdr.set_payload(newdata)
                    tcphdr.tcplen = 20 + len(newdata)
                else:
                    log_info("No changes to data necessary")

                # rewrite destination ethernet address and rebuild packet
                pkt.dst = self.getdst(pkt)
                pkt.payload.payload = tcphdr

                # is this the end of the TCP flow?
                if tcphdr.FIN or tcphdr.RST:
                    log_info("End of TCP flow. Writing to content log")
                    self.writelog(pktkey)

                # send packet back to switch
                log_info("Finished packet: {}".format(pkt.dump()))
                self.net.send_packet(dev, pkt)

        # middlebox is shutting down
        log_info("Shutting down.")

        for key in sorted(self.acont.keys()):
            self.writelog(key)

        self.clog.close()

    def getdst(self, pkt):
        '''
        Computes the ethernet address of the destination
        '''
        n = str(pkt.payload.dstip)[-1]
        dl = "00:00:00:00:00:0" + n
        return EthAddr(dl)

    def writelog(self, key):
        '''
        Appends collected data for application content entry "key" to the content log
        with the format and removes the dictionary entry:
            timestamp\tkey\tapplicationcontent\n
        '''
        line = time.asctime() + "\t" + key + "\t" + self.acont[key] + "\n"
        self.clog.write(line)
        self.clog.flush()
        del self.acont[key]

    def getkey(self, pkt):
        '''
        Generates a key from a packet with the format "srcip:srcport:dstip:dstport"
        '''
        iphd = pkt.payload
        tcphd = pkt.find('tcp')
        return str(iphd.srcip) + ":" + str(tcphd.srcport) + ":" + str(iphd.dstip) + ":" + str(tcphd.dstport)


def srpy_main(net):
    mb = Middlebox(net)
    mb.main()
    net.shutdown()
