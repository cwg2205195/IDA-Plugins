# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
��ȡ��ǰ�������ȣ��ֽ�����
'''

begin = GetFunctionAttr(here(),FUNCATTR_START)
end = GetFunctionAttr(here(),FUNCATTR_END)
print "fun length = 0x%x " %( end - begin)
