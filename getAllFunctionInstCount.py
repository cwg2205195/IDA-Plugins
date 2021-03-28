# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
import os
import collections
func_dic = {}

ea = get_first_seg()

addr = get_next_func(ea)

while addr != BADADDR  :
    func_name = GetFunctionName(addr)                    #get function name 
    inst_count = len(list(idautils.FuncItems(addr)))    #get function instruction count 
    func_dic[func_name] = inst_count
    addr = get_next_func(addr)

sorted_dic = {}
for k in func_dic:            #group functions by instruction count 
    count = func_dic[k]
    try:
        arr = sorted_dic[count]
        arr.append(k)
    except KeyError as e:
        sorted_dic[count] = []
        sorted_dic[count].append(k)
        

keys = sorted(sorted_dic.keys())        #sort functions by instruction count 
func_dic = collections.OrderedDict()
for key in keys:
    func_dic[key] = sorted_dic[key]


f=open("summary.txt","w")
f.write(str(func_dic))
f.close()

print r"output file " + os.getcwd()+"summary.txt"
