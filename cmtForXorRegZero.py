# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
'''
�Զ�ע�ͺ����ڲ��������� �������Ĵ�����ָ��
'''
#��ȡ�����ڵ�����ָ���ַ
dism_addr = list(idautils.FuncItems(here()))


for ea in dism_addr:
	if idc.GetMnem(ea) == 'xor':
		if idc.GetOpnd(ea,0) == idc.GetOpnd(ea,1):	#������������ͬ
			comment = "%s = 0" % (idc.GetOpnd(ea,0))
			idc.MakeComm(ea,comment)