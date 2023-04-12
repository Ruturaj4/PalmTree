# Copyright (c) University of Kansas and affiliates.
import os
import json
import random
import ida_nalt
import idautils
import ida_lines
import networkx as nx
from capstone import *

# capstone for x64
md = Cs(CS_ARCH_X86, CS_MODE_64)
# Wait for auto-analysis to complete.
idc.auto_wait()

def get_symbol_map():
    symbol_map = {}
    for seg in idautils.Segments():
        for seg_ea in range(seg, idc.get_segm_end(seg)):
            if not idc.get_name(seg_ea):
                continue
            symbol_map[seg_ea] = idc.get_name(seg_ea)
    return symbol_map


def get_string_map():
    return {s.ea:str(s) for s in Strings()}


def parse_instruction(ins, symbol_map, string_map):
    ins = re.sub('\s+', ', ', ins, 1)
    parts = ins.split(', ')
    operand = []
    if len(parts) > 1:
        operand = parts[1:]
    for i in range(len(operand)):
        symbols = re.split('([0-9A-Za-z]+)', operand[i])
        for j in range(len(symbols)):
            if symbols[j][:2] == '0x' and len(symbols[j]) >= 6:
                if int(symbols[j], 16) in string_map:
                    symbols[j] = "string"
                elif int(symbols[j], 16) in symbol_map:
                    symbols[j] = "symbol"
                else:
                    symbols[j] = "address"
        operand[i] = ' '.join(symbols)
    opcode = parts[0]
    return ' '.join([opcode]+operand)


def random_walk(g,length, symbol_map, string_map):
    sequence = []
    for n in g:
        if n != -1 and 'text' in g.nodes[n]:
            s = []
            l = 0
            s.append(parse_instruction(g.nodes[n]['text'], symbol_map, string_map))
            cur = n
            while l < length:
                nbs = list(g.successors(cur))
                if len(nbs):
                    cur = random.choice(nbs)
                    if 'text' in g.nodes[cur]:
                        s.append(parse_instruction(g.nodes[cur]['text'], symbol_map, string_map))
                        l += 1
                    else:
                        break
                else:
                    break
            sequence.append(s)
        if len(sequence) > 5000:
            print("early stop")
            return sequence[:5000]
    return sequence


def process_file(window_size):
    symbol_map = get_symbol_map()
    print(symbol_map)
    string_map = get_string_map()
    print(string_map)
    
    function_graphs = {}
    for ea in idautils.Functions():
        G = nx.DiGraph()
        label_dict = {}   
        add_map = {}
        flowchart = idaapi.FlowChart(idaapi.get_func(ea))
        for bb in flowchart:
            curr = bb.start_ea
            predecessor = curr
            while curr < bb.end_ea:
                # Using capstone as ida doesn't give assembly wihtout tags.
                ins_bytes = ida_bytes.get_bytes(curr, idc.get_item_size(curr))
                label_dict[curr] = \
                    " ".join([i.mnemonic+" "+i.op_str for i in md.disasm(ins_bytes, curr)])
                G.add_node(curr, text=label_dict[curr])
                if curr != bb.start_ea:
                    G.add_edge(predecessor, curr)
                predecessor = curr
                curr = idc.next_head(curr)
            for edge in bb.succs():
                G.add_edge(predecessor, edge.start_ea)
        if len(G.nodes) > 2:
            function_graphs[idc.get_func_name(ea)] = G
    
    with open('cfg_train.txt', 'a') as w:
        for name, graph in function_graphs.items():
            sequence = random_walk(graph, 40, symbol_map, string_map)
            for s in sequence:
                if len(s) >= 4:
                    for idx in range(0, len(s)):
                        for i in range(1, window_size+1):
                            if idx - i > 0:
                                w.write(s[idx-i] +'\t' + s[idx]  + '\n')
                            if idx + i < len(s):
                                w.write(s[idx] +'\t' + s[idx+i]  + '\n')        


def main():
    window_size = 1
    process_file(window_size)

if  __name__ == '__main__':
    main()

idc.qexit(0)
