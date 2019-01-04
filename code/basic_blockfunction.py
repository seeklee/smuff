import idaapi
import pickle
import hashlib
import json


idaapi.autoWait()

ops_save_path = idc.ARGV[1]
filename = idc.ARGV[2]

basic_block = []
block_asm_dict = dict()
basic_func = []
func_asm_dict = dict()

for seg_ea in Segments() :
    for func_ea in Functions(seg_ea, SegEnd(seg_ea)):
        f = idaapi.get_func(func_ea)
        func_hash = 0
        func_asm = []
        func_asm.append(func_ea)
        for block in idaapi.FlowChart(f):
            block_asm = []
            block_asm.append(block.startEA)
            block_hash_md5 = hashlib.md5()
            for head in Heads(block.startEA, block.endEA):
                if isCode(GetFlags(head)):
                    block_asm.append(GetDisasm(head))
                    block_hash_md5.update('%02x' % (Byte(head)))
            block_hash = block_hash_md5.hexdigest()
            basic_block.append(block_hash)

            if not len(block_asm) == 0:
                block_asm_dict[block_hash] = block_asm

            if func_hash == 0:
                func_hash = int(block_hash,16)
            else:
                func_hash = func_hash ^ int(block_hash,16)
            func_asm.append(block_asm)

        func_hash = "%032x" % (func_hash)
        basic_func.append(func_hash)

        if not len(func_asm) == 0:
            func_asm_dict[func_hash] = func_asm

if not len(block_asm_dict) == 0:
    with open(ops_save_path +'/block_asm/' + filename + '.json', "w") as f:
        json.dump(block_asm_dict, f, ensure_ascii=True)

if not len(basic_block) == 0:
    with open(ops_save_path +'/block/' + filename + '.block', 'wb') as f:
        pickle.dump(basic_block, f)

if not len(func_asm_dict) == 0:
    with open(ops_save_path +'/func_asm/' + filename + '.json', 'w') as f:
        json.dump(func_asm_dict, f, ensure_ascii=True)

if not len(basic_func) == 0:
    with open(ops_save_path +'/func/' + filename + '.func', 'wb') as f:
        pickle.dump(basic_func, f)

idc.Exit(0)

