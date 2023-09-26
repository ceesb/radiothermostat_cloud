#!/usr/bin/python3
# 
# Crypto for Radiothermostat CT-50. 
#
# License is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse <ceeesb@gmail.com>

from Crypto.Hash import SHA as SHA1
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Hash.HMAC import HMAC

import json

def hmacsha1(key,msg):
	o = HMAC(key,msg=msg,digestmod=SHA1.new())
	return o.digest()

def hmacmd5(key,msg):
	o = HMAC(key,msg=msg,digestmod=MD5.new())
	return o.digest()

def uuid2salt(uuid):
	if len(uuid) == 8:
		return uuid
	elif len(uuid) > 8:
		return uuid[-8:]
	else:
		raise ValueError("wrong length")

def gen_aeskey(uuid,authkey,loops=1000):
	salt = uuid2salt(uuid) + b"\x00\x00\x00\x01"

	ret = hmacsha1(authkey, salt)

	data = ret[:]

	for l in range(1,loops):
		data = hmacsha1(authkey, data)
		ret = bytes([i for i in map(lambda x: x[0]^x[1],zip(ret,data))])
	
	return ret[0:16]

def gen_hashkey(authkey):
	o = MD5.new(authkey[0:8])
	return o.digest()[0:16]

def aes_cbc_decrypt(key,iv,msg):
	o = AES.new(key, AES.MODE_CBC, iv)
	return o.decrypt(msg)

def aes_cbc_encrypt(key,iv,msg):
	o = AES.new(key, AES.MODE_CBC, iv)
	l = len(msg)
	lp = (l + 15) & ~15
	msg = msg + bytes([0 for x in range(0,lp-l)])
	return o.encrypt(msg)

def enc_auth(enckey,authkey,iv,msg):
	if len(enckey) != 16:
		raise ValueError("wrong enckey len")
	if len(iv) != 16:
		raise ValueError("wrong iv len")

	return aes_cbc_encrypt(enckey,iv,hmacmd5(authkey,msg) + msg)

def dec_auth(enckey,authkey,iv,msg):
	if len(enckey) != 16:
		raise ValueError("wrong enckey len")
	if len(iv) != 16:
		raise ValueError("wrong iv len")
	if len(msg) & 15 != 0:
		raise ValueError("msg len not multiple of 16 bytes")

	plain = aes_cbc_decrypt(enckey,iv,msg)
	mac = plain[0:16]
	
	try :
		msg = plain[16:].decode().strip('\x00').encode()
	except Exception:
		raise ValueError("wrong msg")
	
	computedmac = hmacmd5(authkey,msg)

	if mac != computedmac:
		raise ValueError("wrong msg")

	return msg

def create_request(uuid,format_version,eiv,msg):
	jsonhdr = '{"uuid":"'+uuid.decode()+'","format_ver":"'+format_version.decode()+'","eiv":"'+bytes.hex(eiv)+'"}'
	return jsonhdr.encode() + msg

import unittest

class KruptoTest(unittest.TestCase):
	def test5(self):
		authkey = b"11223344"
		uuid = b"aabbccddeeff"

		request = b'{"uuid":"aabbccddeeff","format_ver":"102","eiv":"deadbeef00112233cafebabec335f4c3"}\x07\x86\x9dd\x94\x91qko\x9aE\xf9M\xbd\xfbK\xae\x13\x11\n\xa3\xaa\x81\xc8?,f^\xa5:\xe8\xf4\xea\xca\x9d\x9b\x03\xd3;\xfd\x7f\xe5\xa0\xc6\x91\xban\xbd\xf6\x19*"%\x12\x98\xd9\x94%b]\x99H\xec\x1e\xec\x8d\x17\x07\x03\xbd\xf95x\xbb@\xca@\xbf\xd6\x1b\x06\xa9\xeaE\x15`\x7f\xea\xf6\x15\xf3\xe1I\x9a\xb4qr\xfeD\x92\x1b\x04\xf9z\x05\xbd\x90\x95hL\xb2\x86\x18\x07\xf4*\xdeb\xf8\x8e\xce\x92\xb9f\x92\x19y~(FJ3\xdd\xf9\x02\x08\x12\x94|\xaa\xaf\xfe\x8c\xf4p\xb6h#\xc9(\xe1|\xb9 n\xc9\xea\xb0rRO\xeb\xea\xffzN\x19\xfb\x14.T\xd6\xabpR\x00\xf0\x83\xc3\x85\x8bUR\xfe\x80\x99qX\xffC\xc2\xcbQ\xc9\xad\xb6I\x91\xaf\xacV\x87~\x7fmCsM\xdeX\x9eq\xb7$I\xc6\x88^\xd6\x96((\x85\x19K+a\xdcD]\xf0&\xfb@\xdb\x02\x15\xb2s\xe6\x14\xaeT\xd8\x8c\xc9\xce\xfd`\xc4\x9e\xfe\xe0\xe9 \xaa\xaa\xc4\x86\x0e\xc94#l\xed\xfa\xe5 >\x8b\xf5\xf7\xa0\xa5u\x0c\xab\xb0-2c\x8c=\xcf\xcb\xe15\xb4\x10\xfd?\xc1d\x93\xbb\xf5\x9c@\xb5\xe0\x0fL\xeb\''

		expectedplaintext = b"""{"main_header":{"uuid":"aabbccddeeff","api_version":113,"fw_version":"1.04.84","epoch":10,"sequence":189},"diagnostics":{},"tstat":{"temp":67.50,"tmode":1,"fmode":0,"override":0,"hold":0,"t_heat":59.50,"tstate":0,"fstate":0,"time":{"day":2,"hour":10,"minute":15},"t_type_post":0}}"""

		offset = request.find(b"}")+1
		requesthdr = request[0:offset]
		jsonhdr = json.loads(requesthdr.decode())

		uuid = jsonhdr["uuid"].encode()
		eiv = bytes.fromhex(jsonhdr["eiv"])
		
		aeskey = gen_aeskey(uuid,authkey)
		hashkey = gen_hashkey(authkey)

		requestpayload = request[offset:]
		plaintext = dec_auth(aeskey,hashkey,eiv,requestpayload)

		self.assertTrue(expectedplaintext == plaintext)
		self.assertTrue(requestpayload == enc_auth(aeskey,hashkey,eiv,plaintext))
		self.assertTrue(create_request(uuid,"102".encode(),eiv,requestpayload) == request)

	def test6(self):
		uuid = b"2002af7725c3"
		authkey = b"478b625f"

		request = bytes.fromhex("7b2275756964223a22323030326166373732356333222c22666f726d61745f766572223a22313032222c22656976223a223361373232646433373765626237626364623030376466353463333535636339227d9e8ed80d3c24a10c4332b25e038cd312b1f2fcd2ede860f1c34e6aee59dd2d0060b11158a8de513e5400bc221de9244b99a63e83e501f18c4eedc66c17f40f3242b8cbe4ef707ce4edd7947f1630604497911f3fe4a9d7f83be88a2417f3618ceb15c42a1d8ef19f96afec141d5111eb57b0ae6a841312f06f2639b9453c9a842d00d81ec2b1dcbb61b3ff6be6919be04c76c859e0456e697edb4fc7d6f2139ce98d2f3d2f26da8350f1bcafa57fa3624e030198d21845d781d5d4b7a61182181b895b49eb72946bfb94da1979bb602dfd8478e0fd77a1145ce32058a082299c0ea8ab3fe710c41ff0ce6cc2b177a093d29dca6dad8e1487eb90892e649ff5511d72c1a0114ad01fc881b2e46dc9bdcb44c79cceb3271edc35e7839974e004456444490fc2a5a68edc523964953a820ee2c30f4dc3cedb51c5bf05c80b287301b08b039efabf4e5c5ea256b3662a66b8a156233fc1168adf634a576f0cbc62ddbb41c02b97f763774ff56dfad075bfe96279a9b1d2210c5a68559486dd89fdd04e3dd674dd38834eac14c10c5d0092cd5fe4318f6b043bdfa37c7f6368f93c79f5975165d8d16458f3fca15c1bc8bd51d85ac74741847c482bc3b03b795d8f5ef29c6f46170bfb3e9cdd959477b44ebca0af9809c994d770537cac157fe7a1a6a16504fae770a89e45bf58e0c1a35e4a2aec29c0ef2942db56c7bc69e652f56839051b9420b495dc3705fb4c43bdd9a3ba1b14199d361fcebe939f69666cb32e8094ff59f67dfc2ab06bbd2f114c3dd426061a1da263e582cb3266edb60ae630babdbf50f18842675d3c741d11acf071e09b2ad545b30343f772cb19fee1a72e19789e5a13721bb4c6ffb7bbc35e5989ec056d795b66ed0d414080aed4e2d619cc01e3dfdd92c61aae558049099bb17629d21cded293bbd15d9c8edee550fa7e3602b2a3403e7be05cb0abf96e92bc50ba7c2bd92695e6eb76b3191498b2c2321792fa26c95d7657f44cbc793bfdbfe5b2a35df3b6c0ef56bcf88c279a7b253364478d419c83d934d645f551f980e32584712333c6ffb9973dad622050cd12e64e549308b35c7510224868a23da4f9d74c8ecf380a8cc9fa7658ef64b08574281022abdb4e74229573510b644e07ec287dad5d3891c5042c9ad237c954427adb56db3bf60c99afaf90d54adfb586c6a8d9955431d068b7a8907c591b78b01f5933ae6127be00e5d22b6ce560a78b626cbfecf6ce940a9ecef29bdb5aaa3169048ce08c17d94b1981ee698d23a4aa958ed27b4471dbbe84f1a570e34a5d1cf3ef6e8aaafc48273835842bfbe0f8cc96ae458ec9266ee06cfce95da07f34dbf9a30f0c0dbaacdfe5dde00b7fe17e523af9a79a2b54296ff292d36cfe7c48dca5c7bd61f2f02be54b4ad24a2948556ba26822ab348c49a62fb6fea05d2ddab25a212ca87babeef51c06e428fef41503d057")

		offset = request.find(b"}")+1
		requesthdr = request[0:offset]
		jsonhdr = json.loads(requesthdr.decode())

		uuid = jsonhdr["uuid"].encode()
		eiv = bytes.fromhex(jsonhdr["eiv"])
		
		aeskey = gen_aeskey(uuid,authkey)
		hashkey = gen_hashkey(authkey)

		requestpayload = request[offset:]
		plaintext = dec_auth(aeskey,hashkey,eiv,requestpayload)

		print(len(plaintext))
		print(plaintext)

if __name__ == '__main__':
	unittest.main()
