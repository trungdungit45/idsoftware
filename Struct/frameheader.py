import struct

class frameHeader:
    def __init__(self):
        self.ipsourc  = str()
        self.ipdesti = str()
        self.time = str()
        self.count = int()
       	self.proto = str()
       	self.flagfin = int()
       	self.flagsyn = int()
       	self.flagrst = int()
       	self.flagpsh = int()
       	self.flagack = int()
       	self.flagurg = int()
