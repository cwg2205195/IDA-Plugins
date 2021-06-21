# -*- coding: UTF-8 -*-
# -*- coding:utf-8 -*-

# ======= import =======
import idautils
import idaapi
import idc
from datetime import datetime


class PluginUtil(idaapi.plugin_t):  # 继承 idaapi.plugin_t
    """
    插件类
    """
    flags = idaapi.PLUGIN_UNL
    comment = "jack sparrow plugin util"

    wanted_name = "jack sparrow"  # 插件的名称，在IDA界面导航栏中显示 Edit->Plugins->myplugin
    wanted_hotkey = "Alt-F6"  # 插件的快捷键
    help = "jack sparrow util pluin graph view"

    def init(self): 
        """
        初始化方法
        """
        idaapi.msg(">>> jack sparrow util plugin starts. {0}\n".format(datetime.now()))
        
        # 导入python目录下的功能模块
        idaapi.require("util")
        idaapi.require("util.plugin_util_impl")

        return idaapi.PLUGIN_OK  # return PLUGIN_KEEP
    
    def run(self, arg):
        PluginUtil.PluginUtilImpl.main()  # 注意这里的调用方式是从python中模块的文件夹开始
    
    def term(self):
        idaapi.msg(">>> jack sparrow util plugin ends. {0}\n".format(datetime.now()))


def PLUGIN_ENTRY():
    """
    实例化插件对象
    """
    return PluginUtil()

