from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from atlasnode.protocol.Node.ttypes import *
from atlasnode.protocol.Node import AtlasNode


class NodeClient (object):
    def __init__(self, host, port):
        transport = TSocket.TSocket(str(host), int(port))
        self.transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self.client = AtlasNode.Client(protocol)
    
    def connect(self):
        self.transport.open()
        self.node_info = self.client.getInfo()

    def disconnect(self):
        self.transport.close()
