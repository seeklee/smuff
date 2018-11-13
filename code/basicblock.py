import idaapi
import pickle
import hashlib


idaapi.autoWait()

block_save_path =idc.ARGV[1]
block_detail_save_path =idc.ARGV[2]

basic_block = []
block_asm_dict = dict()

for seg_ea in Segments() :
    for func_ea in Functions(seg_ea, SegEnd(seg_ea)):
        f = idaapi.get_func(func_ea)
        for block in idaapi.FlowChart(f):
            block_asm = []
            block_hash_md5 = hashlib.md5()
            for head in Heads(block.startEA, block.endEA):
                if isCode(GetFlags(head)):
                    block_asm.append(GetDisasm(head))
                    block_hash_md5.update(GetMnem(head))
            block_hash = block_hash_md5.hexdigest()
            basic_block.append(block_hash)

            if not len(block_asm) == 0:
                block_asm_dict[block_hash] = block_asm


if not len(block_asm_dict) == 0:
    with open(block_detail_save_path + '.basm', 'wb') as f:
        pickle.dump(block_asm_dict, f)

if not len(basic_block) == 0:
    with open(block_save_path +'.block', 'wb') as f:
        pickle.dump(basic_block, f)


idc.Exit(0)

