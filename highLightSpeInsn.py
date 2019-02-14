# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
根据当前光标位置，在当前函数内高亮所有 指定的指令
success set_color(long ea, long what, long color);
// color item codes:
#define CIC_ITEM 1          // one instruction or data
#define CIC_FUNC 2          // function
#define CIC_SEGM 3          // segment

#define DEFCOLOR 0xFFFFFFFF     // Default color

'''
colors={'green':0xff00,'red':0xff0000,'yellow':0xffff00,'white':0xffffff,\
'blue':0xff,'default':0xFFFFFFFF}

def HightLight(ea,insn,color):
	#根据 color 指定颜色 高亮函数内所有的 insn
	start = GetFunctionAttr(ea,FUNCATTR_START)
	if start == BADADDR:
		print '无法识别当前函数！'
		return 
	dism_addrs = list(idautils.FuncItems(start))
	for addr in dism_addrs:
		if insn == GetDisasm(addr):
			colorCode=colors[color]
			set_color(addr,CIC_ITEM,colorCode)
			
ea = here()
insn = GetDisasm(ea)
color = AskStr("green","标记的颜色(green,red,yellow,white,blue,default)")
HightLight(ea,insn,color)