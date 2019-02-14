# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
获取当前函数到指定函数的调用路径
注意： call reg 类型可能无法识别
调用的子函数如果是库函数则不进入识别
'''

class Engine:
	def isLibFun(self,funAddr):
		#判断给定地址是否为 库函数
		start = GetFunctionAttr(funAddr,FUNCATTR_START)
		flags = idc.GetFunctionFlags(start)
		return flags & FUNC_LIB

	def isTunkFun(self,funAddr):
		#判断给定地址是否为 trunk fun 
		start = GetFunctionAttr(funAddr,FUNCATTR_START)
		flags = idc.GetFunctionFlags(start)
		return flags & FUNC_THUNK

	def bTraceRegFunAddr(self,dism_addr):
		#反向搜索寄存器调用类型的，函数的地址，并返回
		#参数为当前指令的地址，比如: 401000 call eax 
		
		pass
		
	def getCurCallsAddr(self,funAddr):
		#参数为地址，获取当前函数所有调用的目标函数的地址以及调用指令的地址
		#返回两个列表
		li = []			#返回目标函数地址
		li2 = [] 		#返回当前函数调用目标函数的代码地址
		start = GetFunctionAttr(funAddr,FUNCATTR_START)
		if start == BADADDR:
			return li,li2 
		dism_addrs = list(idautils.FuncItems(start))
		for addr in dism_addrs:
			insn = GetDisasm(addr)
			if 'call' in insn:	
				'''
				call eax, LoadLibrary, ds:GetProcAddr
					reg , near , o_mem , 
				'''
				name = GetOpnd(addr,0)	#获取call 后面的字符串
				OpType = GetOpType(addr,0)	
				if OpType == o_reg:
					#回溯，查找对应寄存器的赋值，找函数的地址
					#print '寄存器调用@ %X\n' % addr 
					pass
				if OpType == o_near:
					nfunAddr = LocByName(name)
					if nfunAddr != BADADDR:
						li.append(nfunAddr)
						li2.append(addr)
				if OpType == o_mem:
					mfunAddr = GetOperandValue(addr,0)
					if mfunAddr != BADADDR:
						li.append(mfunAddr)
						li2.append(addr)
						
		return li,li2

	def recSearch(self,li1,li2,path):
		#递归搜索，第一个参数为函数调用地址列表，
		#第二个参数为函数调用的代码地址列表
		#第三个参数为目标函数的名字
		#第四个参数为当前走过的路径列表，即函数调用关系
		#如果遇到函数调用为目标函数，输出当前路径，然后递归返回
		#否则，进入所有任何非库函数或Trunk函数 的代码调用
		
		if self.curDep >= self.dep :
			return 
		for index in range(0,len(li1)):
			if li1[index] == self.targetAddr:
				self.pid += 1
				print "[%d] path found:\n" % self.pid
				for addr in path:
					print "%X -> " % addr,
				print "%X " % li2[index]
				return 
			elif not self.isLibFun(li1[index]) and not self.isTunkFun(li1[index]):
				liTmp1=[]
				liTmp2=[]
				path.append(li2[index])		#路径添加 当前指令地址
				path.append(li1[index])		#路径添加 下一个要搜索的函数地址
				liTmp1,liTmp2=self.getCurCallsAddr(li1[index])	#获取下一个要搜索的函数的所有函数调用
				self.curDep += 1			#进入一次就递归+1
				self.recSearch(liTmp1,liTmp2,path)	#递归搜索 
				self.curDep -= 1 			#返回后就递归 -1 
				path.pop()
				path.pop()
		
		
	def main(self):
		#主函数，搜索到 target 的路径
		self.targetAddr = LocByName(self.target)
		ea = GetFunctionAttr(here(),FUNCATTR_START)
		if ea == BADADDR :
			print 'no function found here !\n'
			return 
		if self.targetAddr == BADADDR:
			print '%s not found in database\n' % self.target
			return 
		print "start path search from function %s @addr %X" %	(GetFunctionName(ea),ea)
		path = []	#到 target 的所有路径列表
		l=[]	#目标函数地址
		l1=[]	#代码地址
		l,l1 = self.getCurCallsAddr(ea)
		path.append(ea)
		self.pid = 0
		self.recSearch(l,l1,path)
		print "search stopped!\n"
		
	def __init__(self,target,maxDep=1000):
		sys.setrecursionlimit(1500)
		self.curDep = 0		#当前递归深度
		self.dep = maxDep		#设定最大递归深度
		self.target=target	#目标函数地址
		self.pid = 0		#找到的路径数
		self.main()
		
target=AskStr("MessageBoxA","请输入目标函数名")
searchDep=AskStr("1000","所搜深度(设定较小值速度快但结果不全(1 to 5))")
searchDep=int(searchDep)
e=Engine(target,searchDep)