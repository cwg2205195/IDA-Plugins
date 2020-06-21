﻿# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import time 

ImageBase = get_first_seg() - 0x1000         # ---> 当前分析的模块的基址

# 计时器类，停止的时候输出时间间隔
class timer:
    def __init__(self):
        self.startAt=0
    def start(self):
        self.startAt = time.time()
    
    def stop(self):
        stopAt = time.time()
        print("%d seconds elapsed \n" % int(stopAt - self.startAt ))

# 根据 VA 获取函数所引用的字符串列表
'''
输出样例：
{
    0x1234:     // ---> 引用字符串的指令的地址
    "hello world"   // ---> 引用的字符串内容
    ,
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

# 过滤器，减少重复分析， 因为在一个函数内，可能存在多个函数调用，导致重复分析某个函数的字符串引用
def filterVaList(VaList):
    ret = []
    for va in VaList:
        funcAddr = GetFunctionAttr(va,FUNCATTR_START)
        if funcAddr not in ret:
            ret.append(funcAddr)
    return ret

# 把所有线程进行函数调用的 EIP 加入到 字符串引用搜索 列表中
'''
输入样例：
{
    0x1:{   //---->>> 线程ID
        0x1111://---->>> 哈希值
        [1234,4567]//---->>> RVA 列表
    }
}
'''
def work(data):
    count = 0
    t = timer()
    t.start()
    for tid in data.keys():
        VAList = []             # ---> 需要进行字符串引用搜索的地址列表
        for hash in data[tid]:
            rvaList = []
            try:
                rvaList = [rva+ImageBase for rva in data[tid][hash]]
            except Exception as e :
                print(e)
            VAList += rvaList
        
        # 遍历当前线程的所有 va ，获取 va 对应函数所引用的所有字符串
        print("[+]Current thread ID:  " + tid)
        VAList = filterVaList(VAList)
        count += len(VAList)
        for va in VAList:
            #print("va = %x \n" % va)
            result = getStringRefs(va)
            if len(result) == 0:
                continue
            #print(result)
            for key in result.keys():
                print("%x -> %s" % (key,result[key]))
    t.stop()
    print("Total %d VA Analysed" % count)

data ={'0x5': {4970735560114664084: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089], 9104386926033239347: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106], 7740832234702753426: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120], 7759865921512038265: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134], -3206864484571090053: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148], 3709395619791213589: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189], 4391603545210453534: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206], 3962337888505093346: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226], 79226820483085079: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237], 23080457016286843: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257], 5260017737545073168: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276], 680716894156365359: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257], 1775689033098911035: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276], -8788983580307748595: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257], -6408210691972277707: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276], 2449160359092508143: [5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257], 2435086523257279641: [5276, 5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276], 7258772644678994959: [5257, 5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257], -3800504924220944156: [5276, 5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276], 1976307874297564016: [5257, 5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257], 7217148509460076129: [5276, 5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276], 349609373779834092: [5257, 5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257], 4514154598301174691: [5276, 5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276], -2204746703483283181: [5294, 5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257], -4329175563973306325: [5334, 5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276], -6712481616048860775: [5348, 5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257], -1475959669281058338: [5362, 5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276], -5892115962005090959: [5376, 5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257], 715396133559627511: [5393, 5089, 5106, 5120, 5134, 5148, 5189, 5206, 5226, 5237, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276, 5257, 5276]}}

work(data)