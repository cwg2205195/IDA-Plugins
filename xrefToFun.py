# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
'''
根据输入，列出当前函数到指定函数的所有xref
注意：只是当前函数，并没有遍历它调用的子函数是否有 xref 到指定函数 
'''
def getFunType(func):
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_NORET:
		print hex(func), "FUNC_NORET"	#无返回值,常用
	if flags & FUNC_FAR:
		print hex(func), "FUNC_FAR"		
	if flags & FUNC_LIB:
		print hex(func), "FUNC_LIB"		#库函数，常用
	if flags & FUNC_STATIC:
		print hex(func), "FUNC_STATIC"
	if flags & FUNC_FRAME:
		print hex(func), "FUNC_FRAME"	#使用帧的函数，一般有相同的起始代码
	if flags & FUNC_USERFAR:
		print hex(func), "FUNC_USERFAR"
	if flags & FUNC_HIDDEN:
		print hex(func), "FUNC_HIDDEN"
	if flags & FUNC_THUNK:
		print hex(func), "FUNC_THUNK"	#wrap函数，用于跳转到别的函数的函数
	if flags & FUNC_LIB:
		print hex(func), "FUNC_BOTTOMBP"

print "Plugin xrefToFun started\n"

searchDir=SEARCH_DOWN|SEARCH_NEXT
start=GetFunctionAttr(here(),FUNCATTR_START)
end=GetFunctionAttr(start,FUNCATTR_END)
cur_addr = start 
dism_addr = list(idautils.FuncItems(start))

for addr in dism_addr:
	dism = GetDisasm(addr)
	if 'call' in dism:
		x = dism.split(" ")
		name = ''			#检索函数名
		for a in x:
			if len(a)!=0 and a != 'call':
				name=a
				break
		fun_addr = BADADDR
		if name != '':
			fun_addr = LocByName(name)
			getFunType(fun_addr)
			'''if fun_addr != BADADDR:
				flags = GetFunctionFlags(fun_addr)
				if flags & FUNC_LIB:
					print "addr %08X calls libFun %s\n" % (addr,name)
				elif flags & FUNC_THUNK:
					print "addr %08X calls TnkFun %s\n" % (addr,name)'''
		print dism 
print "Plugin xrefToFun stopped!\n"
