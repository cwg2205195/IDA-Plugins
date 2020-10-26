# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import idaapi

# 获取 处理器架构：ARM|metapc 、 位数、 端序
# ret: {'bits': 32, 'cpu': 'ARM', 'endian': 'little'}
def get_arch():
    ret = {}
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
        bits = 16

    try:
        is_be = info.is_be()
    except:
        is_be = info.mf
    endian = "big" if is_be else "little"
    #print 'Processor: {}, {}bit, {} endian'.format(info.procName, bits, endian)
    if info.procName=="metapc":
        ret["platform"]= "x86"
    elif info.procName=="ARM":
        ret["platform"]= "ARM"
    else:
        ret["platform"]="unknown"
    ret["bits"] = bits
    ret["endian"] = endian
    return ret

# 获取函数的属性
# @param funAddr 函数起始地址
def getFuncFlags(funAddr):
    start = get_func_attr(funAddr,FUNCATTR_START)
    flags = idc.GetFunctionFlags(start)
    return flags

# 判断给定地址是否为 库函数
# @param funAddr 函数起始地址
# @returns true|false
def isLibFun(funAddr):
    return getFuncFlags(funAddr) & FUNC_LIB

#判断给定地址是否为 thunk fun 
def isTunkFun(funAddr):
    return getFuncFlags(funAddr) & FUNC_THUNK

# 获取当前函数的所有指令的地址
# def get_func_inst_addr(funAddr):
#     start_addr = GetFunctionAttr(funAddr,FUNCATTR_START)
#     return list(idautils.FuncItems(start_addr))

# 获取给定地址的函数的所有交叉引用
# @param start_addr 函数起始地址
# @param platform 平台： ARM/x86
# @returns 
"""
{
    func_name:"name",

}
"""
def get_ref_funs(start_addr, platform):
    print(start_addr)
    start_addr = get_func_attr(start_addr,FUNCATTR_START)
    if start_addr == BADADDR:
        return {}
    ret = {}
    try:
        ret["func_name"] = get_func_name(start_addr)
        dism_addrs = list(idautils.FuncItems(start))
        for addr in dism_addrs:
            inst = GetDisasm(addr)
            if platform == "x86":
                keyword = "call"
            elif platform == "ARM":
                keyword = "BL"
            else:
                pass
            if keyword in inst:
                name = GetOpnd(addr,0)	#获取call 后面的字符串
                OpType = GetOpType(addr,0)	
                if OpType == o_reg:
                    pass
                elif OpType == o_near:
                    callee_addr = LocByName(name)
                    if callee_addr != BADADDR:
                        ret[callee_addr] = {"func_name":name}
                elif OpType == o_mem:
                    callee_addr = GetOperandValue(addr,0)
                    if callee_addr != BADADDR:
                        ret[callee_addr] = "unknown_mem"
                


    except Exception as e:
        print(e)
    return ret