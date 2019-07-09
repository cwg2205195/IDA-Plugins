# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
获取光标处的 RVA 
'''

ea = here()
rva = ea - get_segm_start(here()) + 0x1000
print hex(rva)

#in x64dbg:
# d mov.base(dis.sel()) + xxx