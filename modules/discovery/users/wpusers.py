#/usr/bin/env python
# -*- Coding: UTF-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)

import re

from lib import wphttp
from lib import wpprint
from distutils.version import StrictVersion

class wpusers:
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
		wpusers.out.test('Enumerate users..')
		users = []
		df_users = []
		self.result.users = []

		# From the version 4.7 the REST API is enabled by default
		if self.result.version and (StrictVersion(self.result.version) >= StrictVersion("4.7")):
			try:
				url = wpusers.chk.path(self.url, "/?rest_route=/wp/v2/users&per_page=100")
				resp = self.req.send(url,c=self.cookie)
				if resp.status_code == 200:
					authors = resp.json()
					for author in authors:
						df_users.append(author['slug'])
			except Exception, e:
				pass

		# Use the normal enumeration method
		for x in range(1,15):
			path = "/?author={}".format(str(x))
			try:
				url = wpusers.chk.path(self.url,path)
				resp = self.req.send(url,c=self.cookie)
				if resp.status_code == 200:
					author = re.findall(r'/author/(.+?)/',resp.content)
					if len(author) == 1:
						if author[0] not in df_users:
							df_users.append(author[0])
					elif len(author) > 1:
						for i in author:
							if i[0] not in df_users:
								df_users.append(author[0])
			except Exception,e:
				pass

		for i in df_users:
			if i not in users:
				users.append(i)

		# Print found users
		if users != []:
			self.result.users = users
			for user in xrange(len(users)):
				if '%20' in users[user][0]:
					wpusers.out.more(' ID: {}  -  Login: {}'.format(user,
						users[user].replace('%20',' ')))
				else:
					wpusers.out.more(' ID: {}  -  Login: {}'.format(user,
						users[user]))
		else:
			wpusers.out.warning('Not found users :(')
