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

debug  = 0
# 获取平台
arch = get_arch()
# print(arch)
# 设置函数过滤，部分函数不跟进，如通用API
func_name_filters = ["print"]

class Engine:
    def __init__(self,depth, arch):
        self.depth = depth  # 设置最大搜索深度
        self.arch = arch

    def rec_search(self, func_entry, depth):
        if debug == 1:
            print("[+]rec_search @ %x depth=%d" %(func_entry, depth))
        # 获取当前函数的所有子函数调用
        refs = get_ref_funs(func_entry,self.arch)
        # 生成 Key  用户获取子函数调用
        k = "%s %x"%(get_func_name(func_entry), func_entry)
        sub_tree = refs[k]
        if debug == 1:
            print("----------------------")
            print("k=%s"%k)
            print(json.dumps(refs))
            print("sub_tree:")
            print(json.dumps( sub_tree))
            print("----------------------")
        if depth > 0 :
            for key in sub_tree:
                try:
                    func_name = sub_tree[key]
                    # 函数名过滤， 预配置的函数不跟进
                    skip = False
                    for name in func_name_filters:
                        if name in func_name :
                            skip = True
                            break
                    if skip == True:
                        continue
                    funAddr = LocByName(func_name)
                    if funAddr != BADADDR:
                        sub_fun_refs = self.rec_search(funAddr,depth - 1)
                        tmp_k = "%s %x"%(func_name, funAddr)
                        refs[k][key] = sub_fun_refs[tmp_k]
                except Exception as e:
                    print("Exception:" + e.message)
                    pass
        return refs

    def start(self, start_addr):
        return self.rec_search(start_addr, self.depth)



# refs = get_ref_funs(here(),arch["platform"])
# print(refs)
search_Depth = AskStr("10","所搜深度(设定较小值速度快但结果不全(1 to 5))")
engine = Engine(int(search_Depth),arch["platform"])
map = engine.start(GetFunctionAttr(here(),FUNCATTR_START))
print("############################")
print(map)
print("############################")
drawer = obj_draw(map)
drawer.draw()
print("############################")
# json.dumps 不要进行排序，否则调用次序会乱
out = json.dumps(map,sort_keys=False)
print(out)
obj = json.loads(out)
print("############################")
drawer = obj_draw(obj)
drawer.draw()
print("############################")
print(obj)
# searchDep=int(searchDep)
# e=Engine(target,searchDep)