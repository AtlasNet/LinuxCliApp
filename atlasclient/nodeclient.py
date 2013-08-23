from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from atlasclient.protocol.Node.ttypes import *
from atlasclient.protocol.Node import AtlasNode


__all__ = ['NodeClient']


class NodeClient (object):
    def __init__(self, host, port):
        transport = TSocket.TSocket(str(host), int(port))
        self.transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self.client = AtlasNode.Client(protocol)
    
    def connect(self):
        self.transport.open()
        self.node_info = self.client.getInfo()

    def postMessage(self, data, key):
        msg = AtlasMessage()
        msg.data = data
        msg.recipientKey = key
        self.client.postMessage(msg)
        
    def disconnect(self):
        self.transport.close()
