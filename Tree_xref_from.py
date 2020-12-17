# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import idaapi
import time
from json import loads
from json import JSONDecoder
import collections
from collections import OrderedDict

custom_decoder = JSONDecoder(object_pairs_hook=OrderedDict)

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

# 获取给定地址的函数的所有交叉引用
# @param start_addr 函数起始地址
# @param platform 平台： ARM/x86
# @returns 
"""
{
    "func_name":{
        "addr_1":"func_name2",
        "addr_2":"func_name3",
    }

}
"""
def get_ref_funs(start_addr, platform):
    start_addr = GetFunctionAttr(start_addr,FUNCATTR_START)
    if start_addr == BADADDR:
        return {}
    ret = collections.OrderedDict()     # 使用有序字典
    try:
        ret["%s %x"%(get_func_name(start_addr), start_addr)] = collections.OrderedDict()
        sub_tree = collections.OrderedDict()
        dism_addrs = list(idautils.FuncItems(start_addr))
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
                sub_tree["%s %x"%(name,addr)] = name
        ret["%s %x"%(get_func_name(start_addr), start_addr)] = sub_tree
    except Exception as e:
        print("exception")
        print(e.message)
    return ret

# 替换字符串 str 特定偏移 offset 的字符为 replacement
# 返回替换的字符串
def replace_char(str, offset, replacement):
    tmp = list(str)
    tmp[offset] = replacement
    return "".join(tmp)

class obj_draw():
    def __init__(self,obj):
        self.obj = obj
        self.path = []
        self.picture = ""

    # 递归进入一层，记录层级以及是否有兄弟节点
    def path_step_in(self, level, has_sibling):
        self.path.append({
            "level": level,
            "has_sibling": has_sibling
        })
    
    # 递归返回一层
    def path_step_out(self):
        ret = self.path.pop()

    # 绘制当前行
    # @param str 展示的数据
    # @param level 对象层级
    def draw_cur_line(self, str, level, has_sibling):
        ret = ""
        if has_sibling == True:
            # notation = '├─'
            notation = '|——'
        else:
            notation = '└─'
        if level == 1:
            # ret =  notation + str.encode('utf8') + "\n"
            ret = str.encode('utf8') + "\n"
        else:
            ret =" " + "  " * level + notation + str.encode('utf8') + "\n"
            # 替换特定位置 " " 为 │
            for node in self.path:
                if node["has_sibling"] == True:
                    ret = replace_char(ret, node["level"]*2 + 1 , "|")
        return ret

    # 绘制当前层的 对象
    def draw_cur_level(self, cur_obj, level):
        # 获取当前节点个数
        item_count = len(cur_obj)
        for key in cur_obj:
            val = cur_obj[key]
            # 当前对象，剩余还未渲染节点个数, --item_count 有问题 - -！
            item_count-=1
            has_sibling = item_count > 0
            if type(val) == str:
                self.picture += self.draw_cur_line(val, level, has_sibling)
            elif type(val) == dict:
                if len(val) == 0:
                    self.picture += self.draw_cur_line(key, level, has_sibling)
                    continue
                self.path_step_in(level, item_count>0)
                self.picture += self.draw_cur_line(key, level, has_sibling)
                self.draw_cur_level(val, level+1)
                self.path_step_out()
            elif type(val) == OrderedDict:
                if len(val) == 0:
                    self.picture += self.draw_cur_line(key, level, has_sibling)
                    continue
                self.path_step_in(level, item_count>0)
                self.picture += self.draw_cur_line(key, level, has_sibling)
                self.draw_cur_level(val, level+1)
                self.path_step_out()
            elif type(val) == unicode:
                self.picture += self.draw_cur_line(val.decode('utf8'), level, has_sibling)
            else:
                #self.picture += self.draw_cur_line(val, level)
                print("unknow type %s" % type(val))
            
    
    def draw(self):
        self.draw_cur_level(self.obj, 1)
        print(self.picture)
        ts_now = time.localtime(time.time())
        uni_name = "picture_"+ str(ts_now.tm_year)+"_" + str(ts_now.tm_mon) + "_"+str(ts_now.tm_mday)+"_"+str(ts_now.tm_hour)+"_"+str(ts_now.tm_min)
        with open(uni_name, "w+") as fout:
            fout.write(self.picture)
            fout.close
            os.system("notepad " + uni_name)


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
# json.dumps 不要进行排序，否则调用次序会乱
out = json.dumps(map,sort_keys=False, ensure_ascii=False)
obj = loads(out ,object_pairs_hook=collections.OrderedDict)
print("############################")
drawer = obj_draw(obj)
drawer.draw()
print("############################")