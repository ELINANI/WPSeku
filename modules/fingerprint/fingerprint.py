#/usr/bin/env python
# -*- Coding: UTF-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)

import waf
import server
import headers
import socket

from lib import wphttp
from lib import wpprint
from urlparse import urlparse

class fingerprint:

	chk = wphttp.UCheck()
	out = wpprint.wpprint()

	def __init__(self,agent,proxy,redir,time,url,cookie,result):
		self.url = url
		self.result = result
		self.cookie = cookie
		self.req = wphttp.wphttp(
			agent=agent,proxy=proxy,
			redir=redir,time=time
			)

	def run(self):
		try:
			resp = self.req.send(self.url,c=self.cookie)
			self.getaddress()
			server.wpserver().run(resp.headers, self.result)
			waf.wpwaf().run(resp._content, self.result)
			headers.wpheaders().run(resp.headers)
			wpprint.wpprint().passs()
		except Exception,e:
			pass

	# Find IP address from a given hostname
	def getaddress(self):
		o = urlparse(self.url)
		try:
			address = socket.gethostbyname(o.netloc)
			self.result.address = address
			wpprint.wpprint().plus('Address: {}'.format(address))
		except Exception as e:
			pass
