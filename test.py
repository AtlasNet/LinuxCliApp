from atlasclient.client import *

c = AtlasClient('test-data')
m = AtlasMessage()
m.blob = 'Hello!'
print c.prepare_message(m, c.contacts[0])
#c.regenerate_key()
c.save()