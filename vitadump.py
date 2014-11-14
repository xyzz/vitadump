import os.path
import struct

from idautils import *
from idc import *

INFO_SIZE = 0x5c
NAME_OFF = 4
NAME_LEN = 27
ENT_TOP_OFF = 0x24
ENT_END_OFF = 0x28
STUB_TOP_OFF = 0x2c
STUB_END_OFF = 0x30

EXPORT_SIZE = 0x20
EXPORT_NUM_FUNCS_OFF = 0x6
EXPORT_LIBNAME_OFF = 0x14
EXPORT_NID_TABLE_OFF = 0x18
EXPORT_ENTRY_TABLE_OFF = 0x1c

IMPORT_SIZE = 0x34
IMPORT_NUM_FUNCS_OFF = 0x6
IMPORT_LIBNAME_OFF = 0x14
IMPORT_NID_TABLE_OFF = 0x1c
IMPORT_ENTRY_TABLE_OFF = 0x20


def u32(s):
    return struct.unpack("<I", s)[0]


def u16(s):
    return struct.unpack("<H", s)[0]


def read_cstring(addr):
    s = ""
    ea = addr
    while True:
        c = Byte(ea)
        if c == 0:
            break
        ea += 1
        s += chr(c)
    return s


def chunk(s, l):
    """
        Chunks S into strings of length L, for example:
        >>> chunk("abcd", 2)
        ["ab", "cd"]
        >>> chunk("abcde", 2)
        ['ab', 'cd', 'e']
    """
    return [s[i:i + l] for i in range(0, len(s), l)]


nid_table = dict()

def load_nids(filename):
    if not os.path.exists(filename):
        print "cannot find nids.txt, NIDs won't be resolved"
        return
    fin = open(filename, "r")
    for line in fin.readlines():
        line = line.split()
        nid_table[int(line[0], 16)] = line[1]
    fin.close()
    print "Loaded {} NIDs".format(len(nid_table))


def resolve_nid(nid):
    if nid in nid_table:
        return nid_table[nid]
    return ""

used_names = dict()

def process_nid_table(nid_table_addr, entry_table_addr, num_funcs, libname, name_suffix=""):
    if num_funcs == 0:
        return

    nids = GetManyBytes(nid_table_addr, 4 * num_funcs)
    funcs = GetManyBytes(entry_table_addr, 4 * num_funcs)
    for nid, func in zip(chunk(nids, 4), chunk(funcs, 4)):
        nid = u32(nid)
        func = u32(func)
        t_reg = func & 1  # 0 = ARM, 1 = THUMB
        func -= t_reg
        for i in range(4):
            SetReg(func + i, "T", t_reg)
        MakeFunction(func)

        actual_name = name = resolve_nid(nid)
        if not name:
            name = "{}_{:08X}".format(libname, nid)
        name = name + name_suffix
        if name in used_names:
            used_names[name] += 1
            name += "_{}".format(used_names[name])
        else:
            used_names[name] = 0

        MakeName(func, name)

        # add a comment to mangled functions with demangled name, but only for imports
        # or otherwise when ida wouldn't do it itself because of non empty suffix
        if actual_name.startswith("_Z") and name_suffix:
            demangled = Demangle(actual_name, GetLongPrm(INF_LONG_DN))
            if demangled != "":
                SetFunctionCmt(func, demangled, 1)


def process_export(exp_addr, libname):
    exp = GetManyBytes(exp_addr, EXPORT_SIZE)
    num_funcs = u16(exp[EXPORT_NUM_FUNCS_OFF:EXPORT_NUM_FUNCS_OFF+2])
    nid_table = u32(exp[EXPORT_NID_TABLE_OFF:EXPORT_NID_TABLE_OFF+4])
    entry_table = u32(exp[EXPORT_ENTRY_TABLE_OFF:EXPORT_ENTRY_TABLE_OFF+4])
    libname_addr = u32(exp[EXPORT_LIBNAME_OFF:EXPORT_LIBNAME_OFF+4])
    if libname_addr:
        libname = read_cstring(libname_addr)
        
    process_nid_table(nid_table, entry_table, num_funcs, libname)


def process_import(imp_addr):
    imp = GetManyBytes(imp_addr, IMPORT_SIZE)
    num_funcs = u16(imp[IMPORT_NUM_FUNCS_OFF:IMPORT_NUM_FUNCS_OFF+2])
    nid_table = u32(imp[IMPORT_NID_TABLE_OFF:IMPORT_NID_TABLE_OFF+4])
    entry_table = u32(imp[IMPORT_ENTRY_TABLE_OFF:IMPORT_ENTRY_TABLE_OFF+4])
    libname_addr = u32(imp[IMPORT_LIBNAME_OFF:IMPORT_LIBNAME_OFF+4])
    if libname_addr:
        libname = read_cstring(libname_addr)

    process_nid_table(nid_table, entry_table, num_funcs, libname, "_imp")


def process_module(module_info_addr):
    module_info = GetManyBytes(module_info_addr, INFO_SIZE)
    name = module_info[NAME_OFF:NAME_OFF+NAME_LEN].strip("\x00")
    ent_top = u32(module_info[ENT_TOP_OFF:ENT_TOP_OFF+4])
    ent_end = u32(module_info[ENT_END_OFF:ENT_END_OFF+4])
    ent_cnt = (ent_end - ent_top) / EXPORT_SIZE
    stub_top = u32(module_info[STUB_TOP_OFF:STUB_TOP_OFF+4])
    stub_end = u32(module_info[STUB_END_OFF:STUB_END_OFF+4])
    stub_cnt = (stub_end - stub_top) / IMPORT_SIZE
    print "Module {} | {} exports, {} imports".format(name, ent_cnt, stub_cnt)

    addr = module_info_addr + INFO_SIZE
    for x in range(ent_cnt):
        process_export(addr, name)
        addr += EXPORT_SIZE

    for x in range(stub_cnt):
        process_import(addr)
        addr += IMPORT_SIZE


def find_modules():
    start = SegStart(ScreenEA())
    end = SegEnd(ScreenEA())
    ea = start
    haystack = "\x00\x00\x01\x01Sce"
    while ea < end:
        if GetManyBytes(ea, len(haystack)) == haystack:
            process_module(ea)
        ea += 4

string_addrs = set()

def find_strings():
    seg_start, seg_end = SegStart(ScreenEA()), SegEnd(ScreenEA())
    bytes = GetManyBytes(seg_start, seg_end - seg_start)

    start = 0
    while start < len(bytes):
        end = start
        while ord(bytes[end]) >= 0x20 and ord(bytes[end]) <= 0x7e:
            end += 1
        if end - start > 5 and not isCode(GetFlags(seg_start + start)):
            string_addrs.add(seg_start + start)
            MakeStr(seg_start + start, BADADDR)
        start = end + 1


def add_string_xrefs():
    """
        Searches for MOV / MOVT pair, probably separated by few instructions,
        and adds xrefs to strings specified in string_addrs
    """
    heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    funcCalls = []
    for addr in heads:
        if GetMnem(addr) == "MOV":
            reg = GetOpnd(addr, 0)
            if GetOpnd(addr, 1)[0] != "#":
                continue
            val = GetOperandValue(addr, 1)
            found = False
            next_addr = addr
            for x in range(5):
                next_addr = NextHead(next_addr)
                if GetMnem(next_addr) in ["B", "BX", "BL", "BLX"]:
                    break
                if GetMnem(next_addr) == "MOVT" and GetOpnd(next_addr, 0) == reg:
                    if GetOpnd(next_addr, 1)[0] == "#":
                        found = True
                        val += GetOperandValue(next_addr, 1) * (2 ** 16)
                    break
                if GetOpnd(next_addr, 0) == reg or GetOpnd(next_addr, 1) == reg:
                    break
            if val in string_addrs:
                add_dref(next_addr if found else addr, val, XREF_USER | dr_O)


def main():
    path = os.path.dirname(os.path.realpath(__file__))
    load_nids(os.path.join(path, "nids.txt"))

    find_modules()
    Wait()
    find_strings()
    add_string_xrefs()


if __name__ == "__main__":
    main()
