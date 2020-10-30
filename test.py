# -*- coding: UTF-8 -*-
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
        },
		"addr_x":"level_n"
    }
}
j={
  "_main 401582": {
    "___main 401588": {},
    "__Z6level5v 40158d": {
      "_printf 401571": "_printf",
      "__Z6level4v 401576": {
        "_printf 401558": "_printf",
        "__Z6level3v 40155d": {
          "_printf 40153a": "_printf",
          "__Z6level2v 40153f": {
            "_printf 401521": "_printf",
            "__Z6level1v 401526": { "_printf 40150d": "_printf" }
          },
          "__Z6level1v 401544": { "_printf 40150d": "_printf" }
        }
      },
      "__Z6level2v 40157b": {
        "_printf 401521": "_printf",
        "__Z6level1v 401526": { "_printf 40150d": "_printf" }
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
第一次错误尝试：
|--_main 401582
|    |--___main 401588
|    |--__Z6level5v 40158d
|    | |--__Z6level4v 401576
|    | | |--_printf
|    | | |--__Z6level3v 40155d
|    | | | |--_printf
|    | | | |--__Z6level1v 401544
|    | | | | |--_printf
|    | | | |--__Z6level2v 40153f
|    | | | | |--_printf
|    | | | | |--__Z6level1v 401526
|    | | | | | |--_printf
|    | |--_printf
|    | |--__Z6level2v 40157b
|    | | |--_printf
|    | | |--__Z6level1v 401526
|    | |   |--_printf
应该在每一层进入下一层时，判断当前层是否 还有未被渲染的 兄弟节点，若没有兄弟节点需要渲染，
则把当前层的 has_sibling 属性设置为 False，这样子孙节点才不会多于的渲染。
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
                    print("found has sibling node at level %d" % node["level"])
                    ret = replace_char(ret, node["level"]*2 + 1, "│")
        return ret

    # 绘制当前层的 对象
    def draw_cur_level(self, cur_obj, level):
        for key in cur_obj:
            val = cur_obj[key]
            if type(val) == str:
                self.picture += self.draw_cur_line(val, level)
            elif type(val) == dict:
                if len(val) == 0:
                    self.picture += self.draw_cur_line(key, level)
                    continue
                self.picture += self.draw_cur_line(key, level)
                self.path_step_in(level+1, len(cur_obj)>1)
                self.draw_cur_level(val, level+1)
                self.path_step_out()
            else:
                pass
    
    def draw(self):
        self.draw_cur_level(self.obj,1 )
        print("[+]Done")
        print(self.picture)


# drawer = obj_draw(j)
# drawer.draw()
content = u"\xe2\x94\x9c "
content.encode('latin1').decode('utf8')
print(content)
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