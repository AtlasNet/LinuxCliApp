all: thrift

thrift:
	mkdir atlasclient/protocol || true
	thrift --gen py:new_style,utf8strings -out atlasclient/protocol Protocols/Node.thrift