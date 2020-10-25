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
        ret["cpu"]= "x86"
    elif info.procName=="ARM":
        ret["cpu"]= "ARM"
    else:
        ret["cpu"]="unknown"
    ret["bits"] = bits
    ret["endian"] = endian
    return ret

# 获取函数的属性
# @param funAddr 函数起始地址
def getFuncFlags(funAddr):
    start = GetFunctionAttr(funAddr,FUNCATTR_START)
    flags = idc.GetFunctionFlags(start)
    return flags

# 判断给定地址是否为 库函数
# @param funAddr 函数起始地址
# @returns true|false
def isLibFun(funAddr):
    return GetFunctionAttr() & FUNC_LIB

#判断给定地址是否为 trunk fun 
def isTunkFun(funAddr):
    return GetFunctionAttr() & FUNC_THUNK