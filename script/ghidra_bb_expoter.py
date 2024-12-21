# -*- coding: utf-8 -*-
#@author marpie (Markus Piéton - marpie@a12d404.net)

import struct
import ghidra.program.model.block.SimpleBlockModel as SimpleBlockModel
import __main__ as ghidra_app


def get_simple_blocks_by_function(image_base, listing):
    model = SimpleBlockModel(ghidra_app.currentProgram)

    entries = {}
    block_iter = model.getCodeBlocks(ghidra_app.monitor)
    while block_iter.hasNext() and (not ghidra_app.monitor.isCancelled()):
        block = block_iter.next()
        for block_addr in block.getStartAddresses():
            if ghidra_app.monitor.isCancelled():
                break
            block_offset = block_addr.getOffset() - image_base

            func_name = block.getName()
            func_offset = 0
            func_offset_rel = 0
            func_of_block = listing.getFunctionContaining(block_addr)
            if func_of_block:
                func_name = func_of_block.getName()
                func_offset = func_of_block.getEntryPoint().getOffset()
                func_offset_rel = func_offset - image_base
                block_offset = block_addr.getOffset() - func_offset
            
            try:
                entries["{}_{}".format(func_offset_rel,func_name)][2].append(block_offset)
            except KeyError:
                entries["{}_{}".format(func_offset_rel,func_name)] = [func_offset_rel, func_name, [block_offset]]
    
    return entries

def run():
    args = ghidra_app.getScriptArgs()
    input_name = ghidra_app.currentProgram.getName()
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}.bb'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = '{}.bb'.format(args[0])
    print("Writing to file : ", output)

    with open(output, "wb") as fd:
        image_base = ghidra_app.currentProgram.getImageBase().getOffset()

        listing = ghidra_app.currentProgram.getListing()

        # Write record type 0 (module)
        # unsigned 16-bit module name
        # And module name
        fd.write(struct.pack("<BH", 0, len(input_name)) + input_name)

        for func_offset, func_name, blocks in get_simple_blocks_by_function(image_base, listing).values():
            # Write record type 1 (function) and unsigned 16-bit function name length
            fd.write(struct.pack("<BH", 1, len(func_name)))
            # Write function name
            fd.write(func_name)

            # Write unsigned 64-bit offset of the function WRT the module base
            fd.write(struct.pack("<Q", func_offset))

            blocks = list(set(blocks))
            blocks.sort()

            blockoffs = bytearray()
            for offset in blocks:
                # Write signed 32-bit offset from base of function
                blockoffs += struct.pack("<i", offset)

            # Unsigned 32-bit number of blocks
            fd.write(struct.pack("<I", len(blockoffs) / 4))
            fd.write(blockoffs)

if __name__ == '__main__':
    run()