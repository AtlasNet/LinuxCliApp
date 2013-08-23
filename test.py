#!/usr/bin/env python
import sys
import os
from atlasclient.client import *
from atlasclient.nodeclient import *

if not os.path.exists('data'):
    os.mkdir('data')
c = AtlasClient('data')
if not c.has_key():
    c.regenerate_key()

if len(sys.argv) == 1:
    print 'test.py mykey'
    print 'test.py regenerate'
    print 'test.py read'
    print 'test.py contacts'
    print 'test.py add "name" "key"'
    print 'test.py remove "name"'
    print 'test.py send "name" "message"'
    print 'test.py send-anon "name" "message"'
    sys.exit(1)

if sys.argv[1] == 'mykey':
    print c.config['public_key']
    sys.exit()

if sys.argv[1] == 'regenerate':
    c.regenerate_key()
    print c.config['public_key']
    sys.exit()

if sys.argv[1] == 'add':
    contact = AtlasContact()
    contact.load({'name': sys.argv[2], 'public_key': sys.argv[3]})
    c.contacts.append(contact)
    c.save()
    sys.exit()

if sys.argv[1] == 'contacts':
    for contact in c.contacts:
        print contact.name
    sys.exit()
    
if sys.argv[1] == 'remove':
    c.contacts = filter(lambda x: x.name != sys.argv[2], c.contacts)
    c.save()
    sys.exit()


nc = NodeClient('ajenti.org', 1957)
nc.connect()

if sys.argv[1] == 'read':
    c.authenticate(nc)
    for listing in nc.client.getListings():
        msg = c.retrieve(listing)
        if msg:
            print 'Message -------'
            print 'Sent:', msg['date']
            if msg['signed']:
                print 'Signed by:', (msg['signed_by'].name if msg['signed_by'] else 'unknown')
            print 'Type:', msg['type']
            print 'Content:', repr(msg['blob'])
            print
    nc.disconnect()
    print 'No more messages'
    sys.exit()

if sys.argv[1].startswith('send'):
    m = AtlasMessage()
    to = None
    for contact in c.contacts:
        if contact.name == sys.argv[2]:
            to = contact
    if not to:
        print 'contact not found'
        sys.exit(1)
    m.blob = sys.argv[3]
    c.post_message(m, to, nc, sign=(sys.argv[1] == 'send'))
    nc.disconnect()
    sys.exit()

