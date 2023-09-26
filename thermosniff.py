#!/usr/bin/python3
# 
# Simple forwarder code for Radiothermostat CT-50. 
#
# License is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse <ceeesb@gmail.com>

from thermocrypto import *
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPConnection
from urllib.parse import urlparse
import argparse
from datetime import datetime,timedelta
from dateutil import tz

def hook_request(request):
	# tweak to change the request from thermostat to cloud
	return request

def hook_response(response):
	# tweak to change the response from cloud to your thermostat
	return response

def get_ThermoServer(aeskey,hashkey,fwdurl):
	class ThermoServer(BaseHTTPRequestHandler):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)

		def mysend_response(self,code,msg):
			print("[x] returning code", code, msg)
			self.send_response(code,msg)

		def do_POST(self):
			content_length = int(self.headers['Content-Length'])
			request = self.rfile.read(content_length)

			offset = request.find(b"}")
			if offset < 0:
				self.mysend_response(400, 'Need a JSON header')
				self.end_headers()
				return

			offset += 1
			requesthdr = request[0:offset]
			try:
				jsonhdr = json.loads(requesthdr.decode())
			except Exception:
				self.mysend_response(400, 'Need a valid JSON header')
				self.end_headers()
				return

			if "uuid" not in jsonhdr:
				self.mysend_response(200, 'No UUID in JSON header')
				self.end_headers()
				return

			if "eiv" not in jsonhdr:
				self.mysend_response(400, 'No EIV in JSON header')
				self.end_headers()
				return
	 
			if len(jsonhdr["eiv"]) != 32:
				self.mysend_response(400, 'Wrong EIV length in JSON header')
				self.end_headers()
				return

			try:
				uuid = jsonhdr["uuid"].encode()
				bytes.fromhex(jsonhdr["uuid"])
			except:
				self.mysend_response(400, 'UUID is not a hexstring in JSON header')
				self.end_headers()
				return

			try:
				eiv = bytes.fromhex(jsonhdr["eiv"])
			except Exception:
				self.mysend_response(400, 'EIV must be hex in JSON header')
				self.end_headers()
				return

			if aeskey == None or hashkey == None:
				self.mysend_response(400, 'No key material to serve this UUID')
				self.end_headers()
				return

			requestpayload = request[offset:]
			
			try:
				requestplaintext = dec_auth(aeskey,hashkey,eiv,requestpayload)
			except Exception:
				self.mysend_response(400, 'Malformed payload after JSON header')
				self.end_headers()
				return

			print("[thermostat to us] =>",requestplaintext.decode())

			responseplaintext = None

			if fwdurl != "":
				patchedrequestplaintext = hook_request(requestplaintext)
				if patchedrequestplaintext != requestplaintext:
					print("[us to backend   ] =>", requestplaintext)
				requestplaintext = patchedrequestplaintext
				requestpayload = enc_auth(aeskey,hashkey,eiv,requestplaintext)
				request = create_request(uuid,b"102",eiv,requestpayload)

				u = urlparse(fwdurl)
				h = HTTPConnection(u.netloc)
				h.request("POST",u.path,body=request)
				r = h.getresponse()
				if r.status != 200:
					self.mysend_response(400, 'Forward URL returns ' + r.status + " " + r.reason)
					self.end_headers()
					return
				response = r.read()
				try:
					responseplaintext = dec_auth(aeskey,hashkey,eiv,response)
				except Exception:
					self.mysend_response(400, 'Forward URL returned malformed response')
					self.end_headers()
					return

				patchedresponseplaintext = hook_response(responseplaintext)
				if patchedresponseplaintext != responseplaintext:
					print("[backend to us   ] <=", responseplaintext)
				responseplaintext = patchedresponseplaintext
			else:
				responseplaintext = b'{"ignore":0}'


			print("[us to thermostat] <=",responseplaintext.decode())
			response = enc_auth(aeskey,hashkey,eiv,responseplaintext)

			self.send_response(200)
			self.send_header("Content-Type", "application/octet-stream")
			self.end_headers()
			self.wfile.write(response)

	return ThermoServer

# curl -d '{"interval": 300, "url": "http://ws.radiothermostat.com/services.svc/StatIn"}' http://192.168.0.11/cloud
# curl -d '{"interval": 30, "url": "http://192.168.0.10:1337"}' http://192.168.0.11/cloud
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("uuid",type=str,help="UUID of thermostat, ex. 112233445566")
	parser.add_argument("authkey",type=str,help="authkey of thermostat, ex. 11223344")
	parser.add_argument("-p", "--port",type=int,help="port on which to start HTTP server",default=8080)
	parser.add_argument("-f", "--fwdurl",type=str,help="URL to forward to",default="")
	args = parser.parse_args()

	uuid = args.uuid.encode()
	authkey = args.authkey.encode()
	fwdurl = args.fwdurl
	port = args.port
	
	aeskey = gen_aeskey(uuid,authkey)
	hashkey = gen_hashkey(authkey)

	myserv = HTTPServer(("", port), get_ThermoServer(aeskey,hashkey,fwdurl))

	try:
		myserv.serve_forever()
	except KeyboardInterrupt:
		pass

	myserv.server_close()
