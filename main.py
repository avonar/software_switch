#!/usr/bin/env python
# -*- coding: utf-8 -*-
import crc16
import sys
from multiprocessing import Process, Lock, Manager, Queue
from scapy.all import *

class Port_listener(Process):
    def __init__(self, sniff_int, ns, q):
        super(Port_listener, self).__init__()
        self.sniff_int = sniff_int
        self.ns = ns
        self.q = q

    def run(self):
        while True:
            p = sniff(iface=self.sniff_int, count=1)
            self.q.put(p)
        sys.exit(1)


class Sender(Process):
    def __init__(self, send_int, packet):
        super(Sender, self).__init__()
        self.send_int = send_int
        self.packet = packet

    def run(self):
        sendp(self.packet, iface=self.send_int)
        sys.exit(1)

def main(ports):
    print 'Starting switch'
    manager = Manager()
    ns = manager.Namespace()
    q = Queue()
    hashtable = {}
    job = []
    for port in ports:
        job = port_listener(port, ns, q)
        jobs.append(job)
        job.start()
    while True:
        item = q.get()
        try:
            hashtable[crc16(item[0][0].hwsrc)] = item[1]
            job = sender(hashtable[crc16(item[0][0].hwdst)], item[0])
            job.start()
        except:
            for port in ports:
                job = sender(port, item[0])
                job.start()


if __name__ == "__main__":
    main(sys.argv[1:])