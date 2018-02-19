#/usr/bin/env python
# -*- Coding: UTF-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)

import sys
import random
import urllib3
import requests
from fake_useragent import UserAgent

class UCheck:
	def payload(self,url,payload):

		if url.endswith('/') & payload.startswith('/'):
			return str(url[:-1]+"?"+payload[1:])

		elif not url.endswith('/') & payload.startswith('/'):
			return str(url+"?"+payload[1:])

		elif url.endswith('/') and not payload.startswith('/'):
			return str(url[:-1]+"?"+payload)

		else:
			return str(url+"?"+payload)

	def path(self,url,path):

		if url.endswith('/') & path.startswith('/'):
			if not path.endswith('/'):
				return str(url[:-1]+path)
			else:
				return str(url+path[:-1])

		elif not url.endswith('/') and not path.startswith('/'):
			if not path.endswith('/'):
				return str(url+"/"+path)
			else:
				return str(url+"/"+path[:-1])

		else:
			if not path.endswith('/'):
				return str(url+path)
			else:
				return str(url+path[:-1])

class wphttp(object):
	ucheck = UCheck()
	ua = UserAgent()

	def __init__(self,**k):
		if "agent" not in k:
			self.agent = None
		else:
			if k["agent"] == "random":
					self.agent = self.ragent()
			else:
				try:
					self.agent = str(self.ua[str(k["agent"])])
				except:
					self.agent = None

		self.proxy = None if "proxy" not in k else k["proxy"]
		self.redir = True if "redir" not in k else k["redir"]
		self.time  = None if "time"  not in k else k["time" ]

	def ragent(self):
		return str(self.ua.random)

	def send(self,u,m="GET",p=None,h=None,c=None):
		if p is None : p = {}
		if h is None : h = {}
		if c is not None : c = {c:''}
		if '-r' in sys.argv or '--ragent' in sys.argv:
			h['user-agent'] = self.ragent()
		else:
			h['user-agent'] = self.agent
		# request
		request = requests.Session()
		req = requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
		# get
		if m.lower()=='get':
			if p: u='{}'.format(Request.ucheck.payload(u,p))
			req = request.request(
				method=m.upper(),url=u,headers=h,cookies=c,timeout=self.time,
				allow_redirects=self.redir,proxies={'http':self.proxy,'https':self.proxy},verify=False)
		# post
		elif m.lower()=='post':
			req = request.request(
				method=m.upper(),url=u,headers=h,cookies=c,timeout=self.time,
				allow_redirects=self.redir,proxies={'http':self.proxy,'https':self.proxy},verify=False)
		# req
		return req
