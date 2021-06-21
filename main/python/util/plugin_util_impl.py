# -*- coding:utf-8 -*-
import idc
import idaapi
import idautils
import sys


def main():
    ea = here()
    rva = ea - get_segm_start(here()) + 0x1000
    print hex(rva)
    print("\nd mod.base(dis.sel()) + %s\n" % hex(rva)[:-1])
    print("\nbp mod.base(dis.sel()) + %s\n" % hex(rva)[:-1])