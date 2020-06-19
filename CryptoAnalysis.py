# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys
'''
各种密码学算法函数的自动识别，重命名，以及结果输出脚本
'''

# 获取给定地址对应函数所引用的所有字符串，返回一个 map， 存储地址和字符串： {0x12345:"test",}
def getStringRefs(addr):
    ret = {}
    start = GetFunctionAttr(addr,FUNCATTR_START)
    if start == BADADDR:
        return ret
    dism_addrs = list(idautils.FuncItems(start))        #获取当前函数 所有指令的地址
    for addr in dism_addrs:
        for i in range(0,2):
            opndType = GetOpType(addr,i)                # 获取指令操作数类型，若是立即数，则判断这个立即数地址是否为一个字符串
            if opndType == o_imm :
                opnd = get_operand_value(addr,i)
                if get_str_type(opnd) == STRTYPE_C:
                    #获取字符串结束符地址，并拷贝
                    string=""
                    offset = 0 
                    while True:
                        val = get_wide_byte(opnd+offset)    #读取一个字节
                        if val == 0:
                            break
                        offset += 1
                        string += chr(val)
                    if string != "":
                        ret[addr]=string
    return ret

class dh_keyExchg:
    def __init__(self):
        self.name = "OpenSSL Diffe-Hellman Key Exchange recognizer"     # sub engine name
         # set_name(here(),,0)
        self.func_name = "compute_key"
        #self.func_proto = "static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)"
        self.func_proto = "static int __cdecl compute_key(void *key, void *pub_key,void *dh);"
        # MakeComm(here(),"")
        self.func_comment = "\nstatic int __cdecl compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);"
        # 保存扫描结果
        self.candidateFuncAddrList = []
        self.scan()

    def scan(self):
        # if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS=10000 = 0x2710)
        self.signature = "10 27"
        # signature for compiler generated string : DHerr(5, 102, 3, ".\\crypto\\dh\\dh_key.c", 250);
        self.signature_str = "dh_key"
        # signature for local variable size
        self.local_var_size = 20
        pos = find_binary(0, 3 | 0x20, "10 27")
        while pos != BADADDR:
            inst = GetDisasm(pos)
            if "cmp" in inst:

                # Found one possible function, add to list
                if pos not in self.candidateFuncAddrList:
                    self.candidateFuncAddrList.append(pos)
            pos = find_binary(pos, 3 | 0x20, "10 27")

        print("All possible address are :")
        print(self.candidateFuncAddrList)
    
    # 根据字符串特征扫描
    def scanBy_Str(self):
        signature = "dh_key"
        str_ref_map = getStringRefs()

    # 根据数字特征扫描
    def scanBy_hexNum(self):
        # if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS=10000 = 0x2710)
        signature = "10 27"
        pos = find_binary(0, 3 | 0x20, signature)
        while pos != BADADDR:
            inst = GetDisasm(pos)
            if "cmp" in inst:

                # Found one possible function, add to list
                if pos not in self.candidateFuncAddrList:
                    self.candidateFuncAddrList.append(pos)
            pos = find_binary(pos, 3 | 0x20, signature)

class SearchEngine:
    def __init__(self):
        print("[+]Crypto Analysis started...")
        self.dh = dh_keyExchg()
        print("[+]Crypto Analysis stoped...")


s = SearchEngine()
