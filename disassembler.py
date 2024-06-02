import os
import sys
import angr
from capstone import *
import string

def is_printable(data, min_length=4):
    """Check if a sequence of bytes is printable."""
    return all(chr(c) in string.printable for c in data) and len(data) >= min_length

def find_main_function(project):
    """Try to find the main function in the binary."""
    # Look for common entry points
    entry_points = ['main', '_start']

    for symbol in project.loader.main_object.symbols:
        if symbol.name in entry_points:
            print(f"Found potential entry point: {symbol.name} at {hex(symbol.rebased_addr)}")
            return symbol.rebased_addr
    
    # Heuristic: Find function with call to exit or similar
    for func in project.kb.functions.values():
        if any("exit" in callee.name for callee in project.kb.functions[func.addr].successors if callee.name):
            print(f"Found potential main function at {hex(func.addr)}")
            return func.addr
    
    print("Main function not found. Defaulting to entry point.")
    return project.entry

def get_successors(cfg, func_addr):
    """Return a list of addresses of the successors for a given function."""
    node = cfg.get_any_node(func_addr)
    if node is None:
        return []
    return [succ.addr for succ in node.successors]

def disassemble_binary(file_path):
    # Load the binary
    project = angr.Project(file_path, auto_load_libs=False)

    # Find the main function or entry point
    main_addr = find_main_function(project)

    # Perform analysis to identify functions and basic blocks
    cfg = project.analyses.CFGFast()

    # Initialize Capstone disassembler
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True  # Enable detailed mode to get instruction details

    # Prepare the output file
    output_file_path = file_path + '.pc'
    with open(output_file_path, 'w') as output_file:
        # Disassemble starting from the main function
        worklist = [main_addr]
        visited = set()

        while worklist:
            func_addr = worklist.pop()
            if func_addr in visited:
                continue
            visited.add(func_addr)

            func = cfg.kb.functions[func_addr]
            output_file.write(f"Function at {hex(func_addr)}:\n")
            
            for block in func.blocks:
                for instruction in md.disasm(block.bytes, block.addr):
                    output_file.write(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\n")
                
                # Add potential data sections within the block
                data_start = block.addr + len(block.bytes)
                data_end = block.addr + block.size
                if data_end > data_start:
                    data_bytes = project.loader.memory.load(data_start, data_end - data_start)
                    if is_printable(data_bytes):
                        output_file.write(f"0x{data_start:x}:\t.ascii\t\"{data_bytes.decode('ascii', errors='ignore')}\"\n")
                    else:
                        output_file.write(f"0x{data_start:x}:\t.byte\t{data_bytes.hex()}\n")
            
            output_file.write("\n")
            worklist.extend(get_successors(cfg, func_addr))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary file>")
        sys.exit(1)

    file_path = sys.argv[1]
    
    # Disassemble the binary
    disassemble_binary(file_path)
