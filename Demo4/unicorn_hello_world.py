from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct

# Constants
ADDRESS = 0x01000000
MEM_MAP_SIZE = 0x00200000

#setup Capstone for disasumbly
cs = Cs(CS_ARCH_X86, CS_MODE_32)

def emulator(X86_CODE32_SHELLCODE):

    KEY_OFFSET = 0xe1
    INTR_OFFSET = 0xc
    arg0_addr = ADDRESS+0x10000

    # callback for tracing EVERY instruction
    def hook_code(uc, address, size, user_data):
        if size > 0x100:
            size = 3
        instructions = uc.mem_read(address,size)
        for i in cs.disasm(instructions,0x100):
            print(f'{i.mnemonic} {i.op_str} :: {instructions.hex()}')
        return True

    # Handles EXCEPTION_ILLEGAL_INSTRUCTION
    def hook_invalid_instruction(uc, user_data):
        r_eip = uc.reg_read(UC_X86_REG_EIP)       
        enc_offset = int.from_bytes(uc.mem_read(r_eip + INTR_OFFSET,1),'little')
        offset = enc_offset ^ KEY_OFFSET
        uc.reg_write(UC_X86_REG_EIP, offset + r_eip)
        print(f'----------- EXCEPTION_ILLEGAL_INSTRUCTION eip=0x{r_eip:X} -----------')
        return True
    
    # Handles EXCEPTION_SINGLE_STEP
    def hook_intr(uc, intno, user_data):
        if intno == 1:
            r_eip = uc.reg_read(UC_X86_REG_EIP)
            enc_offset = int.from_bytes(uc.mem_read(r_eip + INTR_OFFSET,1),'little')
            offset = enc_offset ^ KEY_OFFSET
            print(f'----------- EXCEPTION_SINGLE_STEP eip=0x{r_eip:X} -----------')
            uc.reg_write(UC_X86_REG_EIP, offset + r_eip)
            # clear the trap flag to continue execution
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~0x100)
            return True



    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, MEM_MAP_SIZE)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, X86_CODE32_SHELLCODE)

    # Create stack 0x100 bytes size
    mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0xb100)
    mu.reg_write(UC_X86_REG_EBP, ADDRESS + 0xb200)    
    r_esp = mu.reg_read(UC_X86_REG_ESP)
    mu.mem_write(r_esp+4,struct.pack('<I',arg0_addr))   

    # tracing all instructions with customized callback
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # intercept 2 exceptions !!!
    # mu.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_instruction)
    # mu.hook_add(UC_HOOK_INTR, hook_intr)

    try:
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_SHELLCODE))
    except UcError as e:
        pass

    try:
    # read from memory arg0_addr which is the Arg0
        enc_blob_sz_b = mu.mem_read(arg0_addr, 4)
        enc_blob_sz = struct.unpack('I',enc_blob_sz_b)[0]
        if enc_blob_sz < 1000 and enc_blob_sz > 3:
            enc_blob_b = mu.mem_read(arg0_addr+4, enc_blob_sz)
            print(f'EncSz = {enc_blob_sz}')
            return enc_blob_b
    except UcError as e:
        print(">>> Failed to read enc config bytes")
        return None

    print("Emulation end")

def main():

    SC_bytes_Hex = "8b542404c702d91c409181329f0db05a0fc73bcf0000000000000000f23eb27117ec8081325480fb2651b96c4bbdfe81f1d0e9769781f14accb45581c10a9280c3569c89e6010e9d39ca751696e65d07091e46c0e79bfe16be354a66c6c7ef9db19ec51a3b528107b880fcb15e39d9598102006ff412"
    SC_bytes = bytes.fromhex(SC_bytes_Hex)
    emulator(SC_bytes)

if __name__ == "__main__":
    main()
