# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
from collections import OrderedDict
'''
 仿真执行函数的模拟器
'''

#定义了所有 ARM 下控制流转接指令汇编代码
b_insts=[
"B",
"B.W",
#"BL",		这个是函数调用
"BGT",
"BGT.W",
"BNE",
"BNE.W",
"BEQ",
#"BLX",		这个是函数调用

]

#定义基本块
class basicBlock(object):
	def __init__(self):
		self.name  = ""		#基本块名
		self.start = 0		#起始地址
		self.end   = 0		#结束地址
		self.insts = {}		#所有指令，包括他们的地址，ie：{ 0x1234:"mov R0 , R13 "}
		self.instCount=0	#基本块指令条数
		
#分析函数的基本块列表		
def getFunctionBasicBlocks(insts):
	bbs = []						#初始化空的基本块列表
	curBB = basicBlock()
	curBB.name  = "entry"
	curBB.start = list(insts.keys())[0]	#第一个基本块起始地址
	for addr,inst in insts.items():
		#print("addr %x" % addr)
		operator = inst.split(" ")[0]	#取出操作符
		if operator not in b_insts:
			curBB.instCount += 1
			curBB.insts[addr] = inst
		else:
			curBB.instCount += 1	#当前基本块最后一条指令
			curBB.end = addr		#这个地址要注意，是最后一条指令的起始地址，而不是结束地址
			bbs.append(curBB)
			#print("add new bb , name is : %s " % curBB.name)
			curBB = basicBlock()	#遇到分支，创建新的基本块
			name = "loc_" 
			if ".W" in inst :		#根据基本块第一条指令的地址来命名 基本块 ， 与 ida 相同的命名方式；arm 状态+4字节 ，thumb状态+2字节
				addr += 4
			else:
				addr += 2
			curBB.name = name + str(hex(addr))[2:-1]
			curBB.start= addr 
	
	return bbs 

#获取给定地址的函数的所有指令,及指令的地址
def getFunctionInsts(func_start):
	insts=OrderedDict()				# python 是无序字典，要用有序的
	start = GetFunctionAttr(func_start,FUNCATTR_START)
	#print("Start @ %x" % start )
	if start == BADADDR:
		return insts 
	dism_addrs = list(idautils.FuncItems(start))
	for addr in dism_addrs:
		#print("addr %x " % addr)
		insts[addr]=GetDisasm(addr)
	return insts
	
ea=here()
insts = getFunctionInsts(ea)


'''
for addr,inst in insts.items():
	operator = inst.split(" ")[0]
	if operator in b_insts:
		print("found conditional jump : %x %s" % (addr,inst))
	elif '{R4-R11,LR}' in inst:
		print("------: %x %s" % (addr,inst))
		
'''

bbs = getFunctionBasicBlocks(insts)
print(" block analysis finished")
b=1
for bb in bbs:
	print("block [ %s ] has %d instructions start@ %X and end@ %X " %(bb.name,bb.instCount,bb.start,bb.end) )

