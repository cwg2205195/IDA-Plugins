# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys

def getInsts(funAddr):
    inst = []
    start = GetFunctionAttr(funAddr,FUNCATTR_START)
    if start == BADADDR:
        return inst
    dism_addrs = list(idautils.FuncItems(start))        #获取当前函数 所有指令的地址
    for addr in dism_addrs:
		inst.append(GetDisasm(addr))
    return inst

ea = here()

insts = getInsts(ea)

for inst in insts:
    if 'B' in inst:
        print inst
print "%d instructions in function %s" % (len(insts),GetFunctionName(ea))