#!/usr/bin/python
# hmacBasic.py v0.2
# basic implementation of hmac for server<->server communication for flask

import time
import hmac
import json
import requests
from flask import request, url_for, Flask

# sign message
def send_hmac(*arg): # send_hmac(app, url, request_path, client_ip, json_data)
	# our shared private key, since this is a single key application we don't need a public key (to add one the verification routine needs to get private key based on public key)
	secret = arg[0].config['SECRET_KEY']
	# what time is it? (unix seconds from epoch)
	timenow = time.time()

	# sign JSON message
	if len(arg) > 3:
		digester = hmac.new(secret)
		# the blob we use here is the path of the request that we want to make, the request url, the json data, and the clients timestamp
		digester.update(arg[2]+str(arg[4])+str(arg[3])+str(timenow))
		digest = digester.hexdigest()

		# and send, including the hash and timestamp so that the hash can be recalculated later
		headers = {'Content-Type': 'application/json'}
		r = requests.post(arg[1]+arg[2]+'?timestamp='+str(timenow)+'&hash='+digest, data=json.dumps(arg[3]), headers=headers)

		return r.json()
	# sign url message
	else:
		digester = hmac.new(secret)
        	digester.update(arg[2]+str(arg[3])+str(timenow))
        	digest = digester.hexdigest()

		r = requests.get(arg[1]+arg[2]+'?timestamp='+str(timenow)+'&hash='+digest)

		return r.json()
		
# verify message
def authorize_hmac(app):
    	# single private key application (to add more link to backing store to link public key to private key
	secret = app.config['SECRET_KEY']
	# make sure we were sent the client timestamp and the HMAC hash
	if request.args.get('hash') and request.args.get('timestamp'):
		client_hash = request.args.get('hash')
		# get the timestamp given to us by the client
		client_timestamp = request.args.get('timestamp')

	        # check that the clients timestamp hasn't expired (timestamp+10 minutes), this helps thwart timing attacks
		if time.time() < float(client_timestamp)+float(600):
	        	# verify json message
			if request.json:
				digester = hmac.new(secret)
				# the blob we use here is the path of the request that was made, the json data, the client remote address, and the clients timestamp
				digester.update(request.path+str(request.json)+str(request.remote_addr)+str(client_timestamp))
				digest = digester.hexdigest()
				# true if they match, false if they don't
				return digest == client_hash
			# verify url var message
			else:
				digester = hmac.new(secret)
				# since all the message payload is in the url we only need to blob the request path, client remote addres, and client timestamp
				digester.update(request.path+str(request.remote_addr)+str(client_timestamp))
				digest = digester.hexdigest()
				return digest == client_hash
		else:
			return False
	else:
		return False
