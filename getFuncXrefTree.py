# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import idaapi
from common import *
"""
根据用户指定的递归层级，列出当前函数的交叉引用图。 注意跨平台，支持 x86汇编、arm汇编。
格式：
function_name  call_inst_addr
ie:
rtmp_init 40269e
    PCM_init 4011D9 
        Buffer_init 40acbd 
    H264_init 4011fe 
        Buffer_init 40ace2 
    Buffer_init 401231 
"""


arch = get_arch()
print(arch)

class Engine:
    def __init__(self,depth):
        self.depth = depth  # 设置最大搜索深度


search_Depth = AskStr("1000","所搜深度(设定较小值速度快但结果不全(1 to 5))")
searchDep=int(searchDep)
e=Engine(target,searchDep)