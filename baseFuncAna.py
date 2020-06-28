# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import sys

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

    # 解析一个对象到 funcInfo 
    def parseInfo(self, info):
        self.name = info.name
        self.paramCount = info.paramCount
        self.returnType = info.returnType
        self.varCount = info.varCount
        self.stackFrameSize = info.stackFrameSize
        self.protoType = info.protoType
        self.comment = info.comment
        self.strRefs = info.strRefs
        self.funcCallCount = info.funcCallCount
        self.regFunCallCount = info.regFunCallCount
        self.numRefs = info.numRefs
        self.instRefs = info.instRefs

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
        pos = find_binary(0,3 | 0x20, hexNumStr)
    return ret

# 获取 ea 所属的函数起始地址
def getFuncAddr(ea):
    return get_func_attr(ea, FUNCATTR)

class funcAnalyzer:
    '''
    函数分析器， 根据 函数信息对象， 对IDA中现有的函数，进行自动识别、添加注释，
    如果匹配到的结果有多个，则命名用数字递增，并输出结果到一个对象列表， 由数据展示层展示。
    '''
    def __init__(self, finfo):
        self.funcInf = finfo
        # 保存分析结果列表
        self.results = []
        # 保存匹配的项数
        self.matchCount = 0
        # 保存所有特征的匹配结果
        self.signatureMatchResults = []
    
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
        signature_nums = self.funcInf.numRefs
        # 遍历特征数字，ie [{val:"11 22 33",necessary:true},]
        tmp_signatureMatchResults = []
        for num in signature_nums:
            # 扫描一个特征数字，得到匹配的结果列表
            ret = scanNumRefs(num.val)
            # 构建一个匹配特征结果
            sig = signatureAnaResult(num.val, num.necessary)
            try:
                for ea in ret:
                    sig.addResult(getFuncAddr(ea))
            except Exception as e:
                print(e)
            
            tmp_signatureMatchResults.append(sig)
        
        # 二次筛选，求必要数字特征的交集
        tmp_ = tmp_signatureMatchResults[0]
        inter
        if tmp_ != None and len(tmp_signatureMatchResults) > 1:
            for i in range(len(tmp_signatureMatchResults)):
                tmp_1 = tmp_signatureMatchResults[i]
                if tmp_1.necessary == True and tmp_.necessary == True:
                    self.signatureMatchResults = list(set(tmp_).intersection(set(tmp_1)))
                tmp_ = self.signatureMatchResults


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
        __analyzeByNumRefs()

        __analyzeByStrRefs()
        ######################## 识别函数调用 ########################

        ######################## 筛选函数调用 ########################
        __analyzeByStackFrameSize()

        __analyzeByFunCallCount()

        __analyzeByRegFunCallCount()

        __analyzeByParamCout()

        __analyzeByInstRefs()
        ######################## 筛选函数调用 ########################