# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
'''
自动注释函数内部，所有用 异或清零寄存器的指令
'''
#获取函数内的所有指令地址
dism_addr = list(idautils.FuncItems(here()))


for ea in dism_addr:
	if idc.GetMnem(ea) == 'xor':
		if idc.GetOpnd(ea,0) == idc.GetOpnd(ea,1):	#两个操作数相同
			comment = "%s = 0" % (idc.GetOpnd(ea,0))
			idc.MakeComm(ea,comment)