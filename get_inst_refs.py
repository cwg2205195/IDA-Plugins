# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import os
import collections
func_dic = {}
'''
func_dic example
{
    '0x123456': 'sub_123456',
}
'''
total = 0

ea = get_first_seg()
addr = get_next_func(ea)

# get all function name and addresses
while addr != BADADDR  :
    func_name = GetFunctionName(addr)                    #get function name 
    #print "function %s at %x " % (func_name, addr)
    #inst_count = len(list(idautils.FuncItems(addr)))    #get function instruction count 
    func_dic[addr] = func_name
    addr = get_next_func(addr)
    total += 1

print "total %d functions " % total

# get instructions within funAddr
def getInsts(funAddr):
    inst = []
    start = GetFunctionAttr(funAddr,FUNCATTR_START)
    if start == BADADDR:
        return inst
    dism_addrs = list(idautils.FuncItems(start))        #获取当前函数 所有指令的地址
    for addr in dism_addrs:
		inst.append(GetDisasm(addr))
    return inst

# get instruction reference for specific function
# funAddr - function address
# insts - instructions for reference, ie : ["EOR", "AND", "ORR", "ORN"]
"""
result example:
{
    "function address": {
        "EOR": 3,   # represent for this function has 3 EOR function withn it
        "AND: 0,
    }
}
"""
def get_inst_ref_4_func(funAddr, insts):
    inst_strs = getInsts(funAddr)   # get all instruction within funAddr
    ret = {}
    ret[funAddr] = {}
    tmp_inst_ref_count = 0 # if this is zero , do not save
    if len(inst_strs) > 0:
        for inst in insts :
            ret[funAddr][inst] = 0
            for inst_str in inst_strs :
                if inst in inst_str:
                    ret[funAddr][inst] += 1
                    tmp_inst_ref_count +=1
    return ret, tmp_inst_ref_count

# algorithms most likely used instructions references 
def get_possible_alg_funcs() :
    ret = {}
    #target_insts = ["EOR", "ORR", "ORN"]
    target_insts = ["EOR"]
    for func_addr in func_dic :
        tmp_ret, c = get_inst_ref_4_func(func_addr, target_insts)
        if c > 0:
            ret[func_dic[func_addr]] = tmp_ret
    return ret

data = str(get_possible_alg_funcs())

import tempfile
tmpfd, tempfilename = tempfile.mkstemp()
f=open(tempfilename,"w")
f.write(data)
f.close()

print "output to %s " % tempfilename
