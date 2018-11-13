import idaapi
import pickle
import hashlib


idaapi.autoWait()

function_save_path =idc.ARGV[1]
function_detail_save_path =idc.ARGV[2]

basic_func = []
func_asm_dict = dict()


for seg_ea in Segments() :
    for func_ea in Functions(seg_ea, SegEnd(seg_ea)):
        f = idaapi.get_func(func_ea)
        func_hash = 0
        func_asm = []
        for block in idaapi.FlowChart(f):
            block_asm = []
            block_hash_md5 = hashlib.md5()
            for head in Heads(block.startEA, block.endEA):
                if isCode(GetFlags(head)):
                    block_asm.append(GetDisasm(head))
                    block_hash_md5.update(GetMnem(head))
            block_hash = block_hash_md5.hexdigest()

            if func_hash == 0:
                func_hash = int(block_hash,16)
            else:
                func_hash = func_hash ^ int(block_hash,16)
            func_asm.append(block_asm)

        func_hash = "%032x" % (func_hash)
        basic_func.append(func_hash)

        if not len(func_asm) == 0:
            func_asm_dict[func_hash] = func_asm

if not len(func_asm_dict) == 0:
    with open(function_detail_save_path + '.fasm', 'wb') as f2:
        pickle.dump(func_asm_dict, f2)

if not len(basic_func) == 0:
    with open(function_save_path + '.func', 'wb') as f3:
        pickle.dump(basic_func, f3)

idc.Exit(0)

