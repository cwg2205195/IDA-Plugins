# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys

debug = True

'''
    特征类型
'''
number = 1
string = 2
frameSize = 3
funCallCount = 4
RegFunCallCount = 5
instRef = 6

'''
    引用类型
'''
direct = 1      # 直接引用，即特征存在于函数内部
indirect = 2    # 间接引用，函数内部通过取地址的方式引用特征

class SIGNATURE:
    '''
        特征抽象类， 包含特征类型描述、特征值、匹配特征的地址列表及对应的函数地址
    '''
    # type 表示特征类型， 可选值 string, number, frameSize, funCallCount, RegFunCallCount
    # instRef
    def __init__(self, type):
        self.type = type
        # 保存匹配的特征地址
        self.matchAddrs = []
        # 保存引用该特征的所有函数起始地址
        self.refByFuncs = []
        self.sigRefsDic = dict()

    def setSigName(self, name):
        self.name = name
    
    def setNecessary(self, necessary):
        self.necessary = necessary

    def setVal(self, val):
        self.val = val
    
    # 添加一个引用该特征的函数地址
    def addRefFunc(self, funcAddr):
        if funcAddr not in self.refByFuncs:
            self.refByFuncs.append(funcAddr)

    # 获取所有引用该特征的函数地址列表
    def getRefFunc(self):
        return self.refByFuncs

    '''
        添加一个引用该特征的函数地址
        @param sigAddr  特征的地址
        @param funcAddr 引用该特征的函数地址
        @param refType  引用类型，可能的值： direct、indirect。 
    '''
    def addSigRef(self, sigAddr, funcAddr, refType):
        if sigAddr not in self.sigRefsDic:
            self.sigRefsDic[sigAddr] = dict()
        if funcAddr not in self.sigRefsDic[sigAddr]:
            self.sigRefsDic[sigAddr][funcAddr] = refType

    '''
        获取当前特征的所有引用
    '''
    def getAllRef(self):
        if debug == True:
            print(self.sigRefsDic)
        return self.sigRefsDic

class funcInfo:
    '''函数信息基类，记录函数的各种信息，包括参数个数、返回值类型、函数名、局部变量个数、局部变量空间大小、
    函数原型字符串、函数备注、引用的字符串列表、 调用的函数个数、 指针函数调用的个数（用寄存器调用）、 
    特征常数列表、 特征指令列表、 
    {
        'name': 'KeyExpansion',
        'paramCount': {
            val: 3,
            necessary: true,
        },
        'returnType': {
            val: "void",
            necessary: false,
        },
        'varCount': {
            val: 5,
            necessary: true,
        },
        'stackFrameSize': {
            val: 20,
            necessary: true,
        },
        'protoType': {
            val: "void KeyExpansion(unsigned char*key, Context* ctx)",
            necessary: false,
        },
        'comment': {
            val: "AES key expansion procedure: void KeyExpansion(unsigned char*key, Context* ctx)",
            necessary: false,
        },
        'strRefs': {
            val: [],
            necessary: false,
        },
        'funcCallCount': {
            val: 3,
            necessary: true,
        },
        'regFunCallCount': {
            val: 1,
            necessary: false,
        },
        'numRefs': [{
            val: '11 22 33',
            necessary: true,
        },{
            val: '65 ab de',
            necessary: true,
        }],
        'instRefs': {
            val: [],
            necessary: false,
        },
    }
    '''
    def __init__(self,name):
        # 函数名
        self.name = name
        # 参数个数
        self.paramCount = 0
        # 返回值类型
        self.returnType = "void"
        # 局部变量个数
        self.varCount = 0
        # 局部变量空间 字节大小
        self.stackFrameSize = 0
        # 函数原型字符串
        self.protoType = ""
        # 函数备注，用于加到 F5 的备注上
        self.comment = "Comment for function " + name
        # 引用的字符串列表
        self.strRefs = []
        # 调用的函数个数
        self.funcCallCount = 0
        # 指针函数调用个数（用寄存器调用）
        self.regFunCallCount = 0
        # 特征常数列表， 如 0x1000 等
        self.numRefs = []
        # 特征指令列表， 如 cmp 、 等特殊指令。。。
        self.instRefs = []
        # 保存函数的所有特征
        self.signatures = []

    # 解析一个对象到 funcInfo 
    def parseInfo(self, info):
        try:
            self.name = info["name"]
            #self.paramCount = info["paramCount"]
            #self.returnType = info["returnType"]
            #self.varCount = info["varCount"]
            # self.stackFrameSize = info["stackFrameSize"]
            # self.protoType = info["protoType"]
            # self.comment = info["comment"]
            # self.strRefs = info["strRefs"]
            # self.funcCallCount = info["funcCallCount"]
            # self.regFunCallCount = info["regFunCallCount"]
            self.numRefs = info["numRefs"]
            # self.instRefs = info["instRefs"]
        except Exception as e:
            print(e)
        
    # 添加一个特征到当前函数
    def addSignature(self, signature):
        self.signatures.append(signature)

    # 获取所有数字特征
    def getSigNums(self):
        ret = []
        for i in self.signatures:
            if i.type == number:
                ret.append(i)
        return ret
    
    # 获取特定类型的特征列表
    def getSigByType(self, type):
        ret = []
        for i in self.signatures:
            if i.type == type:
                ret.append(i)
        return ret

class funcAnaResult:
    '''
        函数分析器 分析结果类， 保存匹配的函数地址， 哪些项完全符合，哪些项不完全符合，
        匹配的精确度
    '''
    def __init__(self):
        # 函数地址
        self.va = 0
        # 预估的精确度
        self.accuracy = 0
        # 备注
        self.comment = ""

class signatureAnaResult:
    '''
        保存匹配某个特征的所有结果。
        @param1 signature 特征本身
        @param2 necessary 是否为必要特征
    '''
    def __init__(self, signature, necessary):
        self.signature = signature
        self.necessary = necessary
        self.matches = []            # 存放包含该特征的函数起始地址
    
    def addResult(self, item):
        self.matches.append(item)

# 扫描16进制数， ie: scanNumRefs("11 22 33")
# 返回所有引用的地址ea
def scanNumRefs(hexNumStr):
    ret = []
    pos = find_binary(0,3 | 0x20, hexNumStr)
    while pos != BADADDR:
        if pos not in ret:
            ret.append(pos)
        pos = find_binary(pos,3 | 0x20, hexNumStr)
    if debug == True:
        print("[#]Scan num results: ")
        print(ret)
    return ret

# 获取 ea 所属的函数起始地址
def getFuncAddr(ea):
    return get_func_attr(ea, FUNCATTR_START)

class funcAnalyzer:
    '''
    函数分析器， 根据 函数信息对象， 对IDA中现有的函数，进行自动识别、添加注释，
    如果匹配到的结果有多个，则命名用数字递增，并输出结果到一个对象列表， 由数据展示层展示。
    '''
    def __init__(self, finfo):
        print("\n---------------------------------------\n[+]Initializing analysis for function %s" % finfo.name )
        self.funcInf = finfo
        # 保存分析结果列表
        self.results = []
        # 保存匹配的项数
        self.matchCount = 0
        # 保存所有特征的匹配结果
        self.signatureMatchResults = []
    
    def __makeFunction(self):
        # 获取所有数字类型特征
        signature_nums = self.funcInf.getSigByType(number)
        for sig_num in signature_nums:


    def __analyzeByParamCout(self):
        pass

    def __analyzeByReturnType(self):
        pass

    def __analyzeByStackFrameSize(self):
        pass

    def __analyzeByStrRefs(self):
        pass

    def __analyzeByFunCallCount(self):
        pass

    def __analyzeByRegFunCallCount(self):
        pass

    def __analyzeByNumRefs(self):
        # signature_nums = self.funcInf.numRefs
        signature_nums = self.funcInf.getSigByType(number)
        for sigNum in signature_nums:
            ret =scanNumRefs(sigNum.val)
            if debug == True:
                print("[+]Number ref results :")
                print(ret)
            sigNum.matchAddrs = ret
            # 获取所有引用该特征的函数地址？
            # 遍历找到的特征， 为每一个特征进行交叉引用搜索
            for ea in ret:
                try:
                    va = getFuncAddr(ea)
                    if va != BADADDR:
                        #sigNum.addRefFunc(ea)
                        # 添加一个直接引用
                        sigNum.addSigRef(ea, va, direct)
                    # 搜索间接引用
                    for xref in XrefsTo(ea, 0):
                        # print(xref.type, XrefTypeName(xref.type),' from ', hex(xref.frm), ' to ', hex(xref.to))
                        va = getFuncAddr(xref.frm)  # 获取引用数据的函数地址
                        if va != BADADDR:
                            sigNum.addSigRef(ea, va, indirect)

                except Exception as e:
                    print("Error while finding func start address")
                    print(e)

        if debug == True:
            print("[+]Output all referring functions: ")
            for sigNum in signature_nums:
                sigNum.getAllRef()
                # li = sigNum.getRefFunc()
                # for i in li:
                #     print("%x" % i)
        # 遍历特征数字，ie [{val:"11 22 33",necessary:true},]
        # tmp_signatureMatchResults = []
        # li_signature_num = []
        # print("[+]Debug out signums")
        # print(signature_nums)
        # for num in signature_nums:
        #     # 扫描一个特征数字，得到匹配的结果列表
        #     ret = scanNumRefs(num["val"])
        #     if debug == True:
        #         print("[+]Number ref results :")
        #         print(ret)
        #     # 构建一个匹配特征结果
        #     sig = signatureAnaResult(num["val"], num["necessary"])
        #     li_signature_num.append(num["val"])
        #     try:
        #         for ea in ret:
        #             sig.addResult(getFuncAddr(ea))
        #     except Exception as e:
        #         print(e)
            
        #     tmp_signatureMatchResults.append(sig)
        
        # # 二次筛选，求必要数字特征的交集
        # try:
        #     tmp_ = tmp_signatureMatchResults[0]
        #     intersec = []
        #     if tmp_ != None and len(tmp_signatureMatchResults) > 0:
        #         for i in range(len(tmp_signatureMatchResults)):
        #             tmp_1 = tmp_signatureMatchResults[i]
        #             if debug == True:
        #                 print("\n matches are:")
        #                 print(tmp_.matches)
        #             if tmp_1["necessary"] == True and tmp_["necessary"] == True:
        #                 intersec = list(set(tmp_.matches).intersection(set(tmp_1.matches)))
        #                 tmp_ = signatureAnaResult("",True)
        #                 tmp_.matches = intersec
            
        #     # 添加数字特征到 特征列表
        #     sigNum = signatureAnaResult(li_signature_num, True)
        #     sigNum.matches = tmp_.matches
        #     self.signatureMatchResults.append(sigNum)
        # except Exception as e:
        #     print("[!]Exception")
        #     print(e)
        


    def __analyzeByInstRefs(self):
        pass

    # 开始分析数据库
    def analyze(self):
        # 目前按照自己的经验，做匹配函数 调用优先级的排列
        # 最高级为1，最低级不限。。。
        # 1 数字常量、 2 字符串常量、 3 栈空间大小、 4 函数调用个数
        # 4 寄存器函数调用个数、 4 参数个数、 4 局部变量个数 、
        # 5 引用的指令
        ### 应该是由前几个算法识别主要的函数， 后面几个做进一步筛选。

        ######################## 识别函数调用 ########################
        self.__analyzeByNumRefs()

        self.__analyzeByStrRefs()
        ######################## 识别函数调用 ########################

        ######################## 筛选函数调用 ########################
        self.__analyzeByStackFrameSize()

        self.__analyzeByFunCallCount()

        self.__analyzeByRegFunCallCount()

        self.__analyzeByParamCout()

        self.__analyzeByInstRefs()
        ######################## 筛选函数调用 ########################

# KeyExpansion = {
#     'name': 'KeyExpansion',
#     'numRefs': [{
#             'val': '7b777c63',
#             'necessary': True,
#         }
#     ]
# }

# 创建一个函数
compute_key = funcInfo("compute_key")
# 创建一个特征变量
sig_num = SIGNATURE(number)
sig_num.setSigName("compute_key's signature number")
sig_num.setNecessary(True)
sig_num.setVal("2710")

# 加入到函数特征
compute_key.addSignature(sig_num)
# 创建一个分析器
ana = funcAnalyzer(compute_key)
# 开启分析
ana.analyze()

# 创建一个函数
unsetCheckKey = funcInfo("UncheckedSetKey")
# 创建一个特征变量
sig_num_unsetCheckKey = SIGNATURE(number)
sig_num_unsetCheckKey.setNecessary(True)
sig_num_unsetCheckKey.setVal("7b777c63")
unsetCheckKey.addSignature(sig_num_unsetCheckKey)

# 创建一个分析器
ana = funcAnalyzer(unsetCheckKey)
# 开启分析
ana.analyze()

# DES算法相关函数
DES_set_key_unchecked = funcInfo("DES_set_key_unchecked")
sig_num_DES_set_key_unchecked = SIGNATURE(number)
sig_num_DES_set_key_unchecked.setNecessary(True)
sig_num_DES_set_key_unchecked.setVal("55555555")
DES_set_key_unchecked.addSignature(sig_num_DES_set_key_unchecked)
ana = funcAnalyzer(DES_set_key_unchecked)
ana.analyze()

print("[#]Analyse finished...")
# print(ana.signatureMatchResults)
# info_KeyExpansion = funcInfo("KeyExpansion")
# info_KeyExpansion.parseInfo(KeyExpansion)
# print('numref is ')
# print(info_KeyExpansion.numRefs)
# ana = funcAnalyzer(info_KeyExpansion)

# ana.analyze()
# print("[#]Analyse finished...")
# print(ana.signatureMatchResults)
