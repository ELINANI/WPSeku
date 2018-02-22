#/usr/bin/env python
# -*- Coding: UTF-8 -*-
#
# WPSeku: Wordpress Security Scanner
#
# @url: https://github.com/m4ll0k/WPSeku
# @author: Momo Outaadi (M4ll0k)

from generic import wpgeneric
from plugin import wpplugin
from theme import wptheme
from users import wpusers

from lib import wpprint

class discovery:
	@staticmethod
	def run(agent,proxy,redir,time,url,cookie,result):
		wpgeneric.wpgeneric().run(agent=agent,proxy=proxy,
			redir=redir,time=time,url=url,cookie=cookie,result=result)
		wpprint.wpprint().passs()
		wptheme.wptheme(agent=agent,proxy=proxy,redir=redir,
			time=time,url=url,cookie=cookie,result=result).run()
		wpprint.wpprint().passs()
		wpplugin.wpplugin(agent=agent,proxy=proxy,redir=redir,
			time=time,url=url,cookie=cookie,result=result).run()
		wpprint.wpprint().passs()
		wpusers.wpusers(agent=agent,proxy=proxy,redir=redir,
			time=time,url=url,cookie=cookie,result=result).run()
