# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import time
'''
每隔1分钟保存一次数据库
'''
while True:
	save_database('')
	time.sleep(60)
	
