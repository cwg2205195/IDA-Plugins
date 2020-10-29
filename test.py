# -*- coding: UTF-8 -*-

from common import *
import idc
import idaapi
import idautils
import sys
import idaapi

# inst_addrs = get_func_inst_addr(here())
obj={
    "a":"data",
    "b":"xx",
}
print(obj.values)
for x in obj:
    print(x)
# for xrefs in XrefsFrom(here(),0):
#     print(xrefs.frm)

'''
1. 必须知道来到当前节点的路径
2. 必须知道路径上的所有节点，是否包含兄弟节点，
若存在兄弟节点，必须绘制 | ，而且必须知道层级, 
根据层级，在特定位置绘制 | ，
F:.
├─dex2jar-2.0
│  └─dex2jar-2.0
│      └─lib
├─frida-server-12.6.5-android-arm
├─frida-server-12.6.5-android-x86
├─jd-gui-windows-1.4.0
│  └─jd-gui-windows-1.4.0
├─jeb-2.2.7.201608151620_crack_qtfreet00
│  └─jeb-2.2.7.201608151620_crack_qtfreet00
│      ├─bin
│      │  ├─configuration
│      │  │  ├─org.eclipse.core.runtime
│      │  │  │  └─.manager
│      │  │  ├─org.eclipse.equinox.app
│      │  │  │  └─.manager
'''

class obj_draw():
    def __init__(self,obj):
        self.obj = obj
        self.path = []

    # 递归进入一层，记录层级以及是否有兄弟节点
    def path_step_in(self, level, has_sibling):
        self.path.append({
            "level": level,
            "has_sibling": has_sibling
        })
    
    # 递归返回一层
    def path_step_out(self):
        self.path.pop()

    # 绘制当前行
    # @param str 展示的数据
    # @param level 对象层级
    def draw_cur_line(self, str, level):
        ret = ""
        if level == 1:
            ret = "├─" + str + "\n"
        else:
            ret = "|" + "  " * level + "├─" + str + "\n"
            # 替换特定位置 " " 为 |

    # 绘制当前层的 对象
    def draw_cur_level(self, cur_obj, level):
        for key in cur_obj:
            if type(cur_obj[key]) == str:
                pass
            elif type(cur_obj[key]) == dict:
                pass
            else:
                pass
