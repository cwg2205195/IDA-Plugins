# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
获取当前函数的指令个数
'''
def getInsnCnt(ea):
	start =  GetFunctionAttr(ea,FUNCATTR_START)
	if start == BADADDR:
		print '未能识别出当前的函数起始位置'
		return 
	insn = list(idautils.FuncItems(start))
	print "%s 函数有 %d 条指令\n" % (GetFunctionName(start),len(insn))

ea=here()
getInsnCnt(ea)