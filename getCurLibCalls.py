# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
'''
获取当前函数的所有库函数调用，输出调用地址 和 库函数名
注意：没有列出子函数的库函数调用
还有，如果是用函数指针调用库函数，也无法识别
'''
#遍历当前函数所有指令，获取所有 call 指令的函数名，然后用 LocByName
#获取函数地址，判断是否为 库函数，是则输出名字
print "Plugin getCurLibCalls started\n"
searchDir=SEARCH_DOWN|SEARCH_NEXT
start=GetFunctionAttr(here(),FUNCATTR_START)
end=GetFunctionAttr(start,FUNCATTR_END)
cur_addr = start 
while cur_addr <= end:
	dism = GetDisasm(cur_addr)
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
			if fun_addr != BADADDR:
				flags = GetFunctionFlags(fun_addr)
				if flags & FUNC_LIB:
					print "addr %08X calls libFun %s\n" % (cur_addr,name)
				elif flags & FUNC_THUNK:
					print "addr %08X calls TnkFun %s\n" % (cur_addr,name)
	#print "get next inst\n"
	cur_addr = FindCode(cur_addr,searchDir)
print "Plugin getCurLibCalls stopped!\n"