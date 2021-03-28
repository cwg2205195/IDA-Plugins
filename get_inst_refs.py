# -*- coding: UTF-8 -*-
'''
获取使用 给定指令 的所有函数列表， 下一阶段自动生成 GDB、 frida hook 脚本， 输出日志， 加速定位关键函数。
'''
import idc
import idaapi
import idautils
import sys
import os
import collections
import common
import tempfile
import json
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

func_dic = {}
'''
func_dic example
{
    '0x123456': 'sub_123456',
}
'''
total = 0

ea = get_first_seg()
addr = get_next_func(ea)

# get all function name and addresses
while addr != BADADDR  :
    func_name = GetFunctionName(addr)                    #get function name 
    #print "function %s at %x " % (func_name, addr)
    #inst_count = len(list(idautils.FuncItems(addr)))    #get function instruction count 
    func_dic[addr] = func_name
    addr = get_next_func(addr)
    total += 1

print "total %d functions " % total

# get instructions within funAddr
def getInsts(funAddr):
    inst = []
    start = GetFunctionAttr(funAddr,FUNCATTR_START)
    if start == BADADDR:
        return inst
    dism_addrs = list(idautils.FuncItems(start))        #获取当前函数 所有指令的地址
    for addr in dism_addrs:
		inst.append(GetDisasm(addr))
    return inst

# get instruction reference for specific function
# funAddr - function address
# insts - instructions for reference, ie : ["EOR", "AND", "ORR", "ORN"]
"""
result example:
{
    "262528": {
        "sub_40180": {
            "EOR": 3
        }
    }, 
}
"""
def get_inst_ref_4_func(funAddr, insts, fun_name):
    inst_strs = getInsts(funAddr)   # get all instruction within funAddr
    ret = {}
    ret[fun_name] = {}
    tmp_inst_ref_count = 0 # if this is zero , do not save
    if len(inst_strs) > 0:
        for inst in insts :
            ret[fun_name][inst] = 0
            for inst_str in inst_strs :
                if inst in inst_str:
                    ret[fun_name][inst] += 1
                    tmp_inst_ref_count +=1
    if tmp_inst_ref_count > 0 :
        Jump(funAddr)
        print "function %s %X has %d counts of %s \n" % (GetFunctionName(funAddr), funAddr, tmp_inst_ref_count, insts[0])
    return ret, tmp_inst_ref_count

# algorithms most likely used instructions references 
def get_possible_alg_funcs() :
    ret = {}
    #target_insts = ["EOR", "ORR", "ORN"]
    target_insts = ["EOR"]
    for func_addr in func_dic :
        tmp_ret, c = get_inst_ref_4_func(func_addr, target_insts, func_dic[func_addr])
        if c > 0:
            ret[func_addr] = tmp_ret
    return ret

hook_fun_template = """
try{
    hooker.hook({
            mod_name: "%s",     // replace with module name 
            fun_addr: 0x%x,       // replace with function address
            fun_before: function (args, _this) {
                send("[+]call %s ****************************");     // replace with function name
            },
            fun_after: function (retval, _this) {
                send("[+]Leaving %s ****************************")     // replace with function name
            }
    })
}catch(e) {
    console.log(e)
}
"""
hook_caller = """
Java.perform(function () {
    send("[+]Start hooking ")
    %s
    send("[+]Finish hooking ")
});
"""
# generate frida hook scripts...
# addr_list - list of addresses to hook ... [0x1234, 0x5678, ]
def gen_frida_hook_script(addr_list):
    # get module name
    module_name = get_idb_path().split("\\")[-1].split(".")[0]

    # get platform info
    arch = get_arch()
    if arch["platform"] == "x86" :
        module_name += ".dll"
    elif arch["platform"] == "ARM" :
        module_name += ".so"
    
    py_script_path = os.path.split(os.path.realpath(__file__))[0]
    template_file_name = py_script_path + "\\frida_hook_template.js"
    with open(template_file_name,"r") as f:
        script_content = f.read()
        f.close()
    
    whole_line = ""
    for fun_addr in addr_list:
        fun_name = GetFunctionName(fun_addr)
        script_line = hook_fun_template % (module_name, fun_addr, fun_name, fun_name)
        whole_line += script_line
    print "whole line %s " % whole_line
    scripts_ = hook_caller % whole_line
    fd,tmp_js_file = tempfile.mkstemp()
    tmp_js_file += ".js"
    with open(tmp_js_file, "w") as f:
        f.write(script_content)
        f.write(scripts_)
        f.close()
        print "frida hook script generate at %s " % tmp_js_file
    pass


info = get_possible_alg_funcs() # get the result
data = str(json.dumps(info, indent=4)) # dump to json


tmpfd, tempfilename = tempfile.mkstemp()
tempfilename += ".json"
f=open(tempfilename,"w")
f.write(data)
f.close()

print "output to %s " % tempfilename

#print os.path.split(os.path.realpath(__file__))[0]
gen_frida_hook_script(info.keys())