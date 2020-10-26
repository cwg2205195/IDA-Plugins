# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys

'''
获取函数引用的所有字符串，返回引用这个字符串的地址 和 字符串
如：
{
    0x123456:"hello world",
}
'''

def getStringRefs(addr):
    ret = {}
    start = GetFunctionAttr(addr,FUNCATTR_START)
    if start == BADADDR:
        return ret
    dism_addrs = list(idautils.FuncItems(start))        #获取当前函数 所有指令的地址
    for addr in dism_addrs:
        for i in range(0,2):
            opndType = GetOpType(addr,i)                # 获取指令操作数类型，若是立即数，则判断这个立即数地址是否为一个字符串
            if opndType == o_imm :
                opnd = get_operand_value(addr,i)
                if get_str_type(opnd) == STRTYPE_C:
                    #获取字符串结束符地址，并拷贝
                    string=""
                    offset = 0 
                    while True:
                        val = get_wide_byte(opnd+offset)    #读取一个字节
                        if val == 0:
                            break
                        offset += 1
                        string += chr(val)
                    if string != "":
                        ret[addr]=string
    return ret 

ea = here()

result=getStringRefs(ea)

seg_start = get_segm_start(ea)

print("########################### get current function string refs begin ###########################")
#print("seg start @ %x" % seg_start)
for key in result.keys():
    print("%x [ d mod.base(dis.sel()) + 0x%x ] -> %s" % (key, key-seg_start + 0x1000, result[key]))

print("########################### get current function string refs end ###########################")

