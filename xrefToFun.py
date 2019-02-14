# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
'''
�������룬�г���ǰ������ָ������������xref
ע�⣺ֻ�ǵ�ǰ��������û�б��������õ��Ӻ����Ƿ��� xref ��ָ������ 
'''
def getFunType(func):
	flags = idc.GetFunctionFlags(func)
	if flags & FUNC_NORET:
		print hex(func), "FUNC_NORET"	#�޷���ֵ,����
	if flags & FUNC_FAR:
		print hex(func), "FUNC_FAR"		
	if flags & FUNC_LIB:
		print hex(func), "FUNC_LIB"		#�⺯��������
	if flags & FUNC_STATIC:
		print hex(func), "FUNC_STATIC"
	if flags & FUNC_FRAME:
		print hex(func), "FUNC_FRAME"	#ʹ��֡�ĺ�����һ������ͬ����ʼ����
	if flags & FUNC_USERFAR:
		print hex(func), "FUNC_USERFAR"
	if flags & FUNC_HIDDEN:
		print hex(func), "FUNC_HIDDEN"
	if flags & FUNC_THUNK:
		print hex(func), "FUNC_THUNK"	#wrap������������ת����ĺ����ĺ���
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
		name = ''			#����������
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
