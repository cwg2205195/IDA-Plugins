import json
j = {
    "func_name":"level_1",
    "addr_1":{
        "func_name":"level_2",
        "addr_3":{
            "func_name":"level_3",
            "addr_4":{
                "addr_5":"CreateWindow",
                "addr_6":"UpdateWindow"
            }
        }
    }
}
# x = json.dumps(j,sort_keys=False,indent=4,separators={",",":"})
x = json.dumps(j,sort_keys=False,indent=4 )
# print(x)
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
        self.path.pop()

    # 绘制当前行
    # @param str 展示的数据
    # @param level 对象层级
    def draw_cur_line(self, str, level):
        ret = ""
        if level == 1:
            ret = "├─" + str + "\n"
        else:
            ret = "│" + "  " * level + "├─" + str + "\n"
            # 替换特定位置 " " 为 │
            for node in self.path:
                if node["has_sibling"] == True:
                    replace_char(ret, node["level"]*2 , "│")
        return ret

    # 绘制当前层的 对象
    def draw_cur_level(self, cur_obj, level):
        for key in cur_obj:
            val = cur_obj[key]
            if type(val) == str:
                self.picture += self.draw_cur_line(val, level)
            elif type(val) == dict:
                if len(val) == 0:
                    continue
                self.picture += self.draw_cur_line(key, level)
                self.draw_cur_level(val, level+1)
            else:
                pass
    
    def draw(self):
        self.draw_cur_level(self.obj,1 )
        print("[+]Done")
        print(self.picture)


drawer = obj_draw(j)
drawer.draw()

# obj = json.loads(x)

# class drawer():
#     def __init__(self,obj):
#         self.target = obj

#     def draw_the_map(self, curr_obj, depth):
#         if type(curr_obj) != dict:
#             return "\t" * depth + str(curr_obj) + "\n"
#         ret = ""
#         for k in curr_obj:
#             ret += "\t" * depth +  k + "\n"
#         return ret
    
#     def rec_draw(self, curr_obj, depth):
#         print("dep=%d" % depth)
#         print("obj=")
#         print(curr_obj)
#         print("obj type =")
#         print(type(curr_obj))
#         ret = ""
#         for key in curr_obj:
#             ret += self.draw_the_map(curr_obj[key],depth + 1)
#         print("ret = %s " % ret)
#         return ret 
    
#     def draw(self):
#         depth = 1
#         ret = self.rec_draw(self.target,depth)
#         return ret

# d = drawer(j)
# print(d.draw())
# for k in obj:
#     print(k)
# print("\n")
# l = ["hunter","apple"]
# b="er"
# for name in l:
#     if b in name:
#         print("b in name")

# print("GO")
# print("\n"*5)
# print("Go")