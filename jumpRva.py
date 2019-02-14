# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
跳转到指定RVA地址
'''

rva = AskStr('0','输入RVA(16进制)')
rva = int(rva,base=16)
jumpto( get_segm_start(here())+rva)