# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import idaapi
sys.path.append('.')
import common
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
    def __init__(self,depth, arch):
        self.depth = depth  # 设置最大搜索深度
        self.arch = arch

    def rec_search(self, func_entry, depth):
        refs = get_ref_funs(func_entry,self.arch)
        k = "%s %x"%(get_func_name(func_entry), func_entry)
        # print("k=%s"%k)
        # print(refs)
        sub_tree = refs[k]
        print("sub_tree\n")
        print(sub_tree)
        for key in sub_tree:
            # print(key)
            func_name = sub_tree[key]
            # print("key %s" % key)
            # print(func_name)
            # print("funname: %s" %func_name)
            funAddr = LocByName(func_name)
            if funAddr != BADADDR and depth > 0:
                sub_fun_refs = self.rec_search(funAddr,depth - 1)
                sub_tree[key] = sub_fun_refs
        return refs

    def start(self, start_addr):
        return self.rec_search(start_addr, self.depth)



# refs = get_ref_funs(here(),arch["platform"])
# print(refs)
engine = Engine(5,arch["platform"])
map = engine.start(GetFunctionAttr(here(),FUNCATTR_START))
print(map)
# search_Depth = AskStr("1000","所搜深度(设定较小值速度快但结果不全(1 to 5))")
# searchDep=int(searchDep)
# e=Engine(target,searchDep)