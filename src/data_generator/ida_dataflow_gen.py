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

def process_file():
    pass


def main():
    window_size = 1
    process_file(window_size)

if  __name__ == '__main__':
    main()

idc.qexit(0)