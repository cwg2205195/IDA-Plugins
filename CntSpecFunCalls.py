# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
计算当前函数，调用特定函数的次数

'''

def getSpecFunCalls(targetAddr):
	start = GetFunctionAttr(here(),FUNCATTR_START)
	dism_addrs = list(idautils.FuncItems(start))
	count  =0 
	for addr in dism_addrs:
			insn = GetDisasm(addr)
			if 'call' in insn:	
			
				name = GetOpnd(addr,0)	#获取call 后面的字符串
				OpType = GetOpType(addr,0)	
				if OpType == o_reg:
					#回溯，查找对应寄存器的赋值，找函数的地址
					#print '寄存器调用@ %X\n' % addr 
					pass
				if OpType == o_near:
					nfunAddr = LocByName(name)
					if nfunAddr == targetAddr:
						count += 1
						print '[%d] %x ' % (count,addr )
				if OpType == o_mem:
					mfunAddr = GetOperandValue(addr,0)
					if mfunAddr == targetAddr:
						count += 1
						print '[%d] %x ' % (count,addr ) 

func = AskStr("MessageBoxA","输入函数名或函数地址")	

try:
	targetAddr=int(func,16)
except ValueError:
	targetAddr=LocByName(func)
finally:
	print 'fun addr %x ' % targetAddr
	getSpecFunCalls(targetAddr)
					
						
