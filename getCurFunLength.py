# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
获取当前函数长度（字节数）
'''

begin = GetFunctionAttr(here(),FUNCATTR_START)
end = GetFunctionAttr(here(),FUNCATTR_END)
print "fun length = 0x%x " %( end - begin)
