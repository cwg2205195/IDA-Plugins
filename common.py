# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import idaapi
import collections

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
    "func_name":{
        "addr_1":"func_name2",
        "addr_2":"func_name3",
    }

}
"""
def get_ref_funs(start_addr, platform):
    # print(start_addr)
    start_addr = GetFunctionAttr(start_addr,FUNCATTR_START)
    if start_addr == BADADDR:
        return {}
    ret = collections.OrderedDict()     # 使用有序字典
    # print("[+]Funstart@ %x" %start_addr)
    try:
        ret["%s %x"%(get_func_name(start_addr), start_addr)] = collections.OrderedDict()
        # print(ret)
        sub_tree = collections.OrderedDict()
        dism_addrs = list(idautils.FuncItems(start_addr))
        # print(dism_addrs)
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
        print("step in level %d has sibling %d"%(level, has_sibling))
        self.path.append({
            "level": level,
            "has_sibling": has_sibling
        })
        print(self.path)
    
    # 递归返回一层
    def path_step_out(self):
        ret = self.path.pop()
        print("step out")
        print(ret)

    # 绘制当前行
    # @param str 展示的数据
    # @param level 对象层级
    def draw_cur_line(self, str, level):
        ret = ""
        if level == 1:
            ret = "|--" + str + "\n"
        else:
            ret = "|" + "  " * level + "|--" + str + "\n"
            # 替换特定位置 " " 为 │
            for node in self.path:
                if node["has_sibling"] == True:
                    ret = replace_char(ret, node["level"]*2 + 1, "|")
        return ret

    # 绘制当前层的 对象
    def draw_cur_level(self, cur_obj, level):
        # 获取当前节点个数
        item_count = len(cur_obj)
        print("level %d has %d nodes" % (level, item_count))
        for key in cur_obj:
            val = cur_obj[key]
            # 当前对象，剩余还未渲染节点个数
            --item_count
            if type(val) == str:
                self.picture += self.draw_cur_line(val, level)
            elif type(val) == dict:
                if len(val) == 0:
                    self.picture += self.draw_cur_line(key, level)
                    continue
                self.path_step_in(level, item_count>1)
                self.picture += self.draw_cur_line(key, level)
                self.draw_cur_level(val, level+1)
                self.path_step_out()
            elif type(val) == unicode:
                self.picture += self.draw_cur_line(val.decode('utf8'), level)
            else:
                #self.picture += self.draw_cur_line(val, level)
                print("unknow type %s" % type(val))
            
    
    def draw(self):
        self.draw_cur_level(self.obj, 1)
        print("[+]Done")
        print(self.picture)
