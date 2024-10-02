import yara
from unicorn import *
from unicorn.x86_const import *
import struct
from capstone import *
import re
import logging
from typing import Optional, List

# Constants
KEY_OFFSET = 0xe1
INTR_OFFSET = 0xc
ADDRESS = 0x01000000
MEM_MAP_SIZE = 0x00200000


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

cs = Cs(CS_ARCH_X86, CS_MODE_32)

def emulator(X86_CODE32_SHELLCODE):
    KEY_OFFSET = 0xe1
    INTR_OFFSET = 0xc

    arg0_addr = ADDRESS+0x10000

    # callback for tracing instructions
    def hook_code(uc, address, size, user_data):
        illegal_instr = [
        bytearray(b'\x0f\x01\xc4'),
        bytearray(b'\x0f\x07'),
        bytearray(b'\x0f\x01\xf2'),
        bytearray(b'\xf4'),
        bytearray(b'\x0f\x09'),
        bytearray(b'\x0f\x32'),
        bytearray(b'\x0f\x06'),
        bytearray(b'\x0f\x08'),
        bytearray(b'\x0f\x30'),
        bytearray(b'\x0f\xc7\x31'),
        bytearray(b'\x0f\xc7\x36'),
        bytearray(b'\x0f\xc7\x30'),
        bytearray(b'\x0f\xc7\x3b'),
        bytearray(b'\x0f\x00\x11'),
        bytearray(b'\x0f\x00\x16'),
        bytearray(b'\x0f\x00\x19'),
        bytearray(b'\x0f\x00\xd8'),
        bytearray(b'\x0f\x00\xda'),
        bytearray(b'\x0f\x00\x10'),
        bytearray(b'\x0f\x00\xd9'),
        bytearray(b'\x0f\x01\x10'),
        bytearray(b'\x0f\x01\x12'),
        bytearray(b'\x0f\x01\x19'),
        bytearray(b'\x0f\x00\x12'),
        bytearray(b'\x0f\x00\x13'),
        bytearray(b'\x0f\x00\xdb'),
        bytearray(b'\x0f\x01\x11'),
        bytearray(b'\x0f\x01\x16'),
        bytearray(b'\x0f\x01\x17'),
        bytearray(b'\x0f\x01\x36'),
        bytearray(b'\x0f\x01\xc4'),
        bytearray(b'\x0f\x01\x1a'),
        bytearray(b'\x0f\x01\xc8'),
        bytearray(b'\x0f\x01\xf0'),
        bytearray(b'\x0f\x01\xf1'),
        bytearray(b'\x0f\x01\xf3'),
        bytearray(b'\x0f\x01\xf6'),
        bytearray(b'\x0f\x01\xf7'),
        bytearray(b'\x0f\x01\x18'),
        bytearray(b'\x0f\x01\x30'),
        bytearray(b'\x0f\x01\x1f'),
        bytearray(b'\x0f\x01\x1b'),
        bytearray(b'\x0f\x00\xdf'),
        bytearray(b'\x0f\x01\x13'),
        bytearray(b'\x0f\x01\x31'),
        bytearray(b'\x0f\x01\x32'),
        bytearray(b'\x0f\x01\x37'),
        bytearray(b'\x0f\x01\x14\x24'),
        bytearray(b'\x0f\x01\x55\x00'),
        bytearray(b'\x0f\x00\x14\x24'),
        bytearray(b'\x66\x0f\xc7\x32'),
        bytearray(b'\x0f\x01\x1c\x24'),
        bytearray(b'\x0f\x00\x55\x00'),
        bytearray(b'\x0f\x01\x5d\x00'),
        bytearray(b'\xf3\x0f\xc7\x31')
            ]
        try:
            uc.mem_unmap(0, 0x00020000)
        except UcError:
            pass
        # print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
        if size > 0x100:
            size = 3

        instructions = uc.mem_read(address,size)
        # for i in cs.disasm(instructions,0x100):
            # print(f'{i.mnemonic} {i.op_str} {instructions.hex()}')
        if size < 6:
            if instructions in illegal_instr:
                r_eip = uc.reg_read(UC_X86_REG_EIP)
                # print("Invalid instruction EXCEPTION_: 0x{:x}".format(r_eip))       
                enc_offset = int.from_bytes(uc.mem_read(r_eip + INTR_OFFSET,1),'little')
                offset = enc_offset ^ KEY_OFFSET
                uc.reg_write(UC_X86_REG_EIP, offset + r_eip)
        return True

    # callback for tracing invalid memory access (READ or WRITE)
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE_UNMAPPED:
            # print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
            #         %(address, size, value))
            r_eip = uc.reg_read(UC_X86_REG_EIP)       
            enc_offset = int.from_bytes(uc.mem_read(r_eip+ INTR_OFFSET,1),'little')
            offset = enc_offset ^ KEY_OFFSET
            uc.reg_write(UC_X86_REG_EIP, offset + r_eip)
            registers = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI] 
            for reg in registers:
                val = uc.reg_read(reg)
                if val == address:
                    uc.mem_map(0, 0x00020000)
                    return True
        else:
            return False

    def hook_invalid_instruction_0(uc, user_data):
        r_eip = uc.reg_read(UC_X86_REG_EIP)       
        enc_offset = int.from_bytes(uc.mem_read(r_eip + INTR_OFFSET,1),'little')
        offset = enc_offset ^ KEY_OFFSET
        uc.reg_write(UC_X86_REG_EIP, offset + r_eip)
        # print(" Invalid instruction EXCEPTION_: 0x{:x}".format(r_eip))
        return True

    def hook_intr(uc, intno, user_data):
        if intno == 3:
            r_eip = uc.reg_read(UC_X86_REG_EIP)
            enc_offset = int.from_bytes(uc.mem_read(r_eip -1 + INTR_OFFSET,1),'little')
            offset = enc_offset ^ KEY_OFFSET
            uc.reg_write(UC_X86_REG_EIP, offset + r_eip -1)
            # print(f'EXCEPTION_BREAKPOINT eip=0x{r_eip:X} offset=0x{offset:X}')
            return True
        if intno == 1 or intno == 13: 
            r_eip = uc.reg_read(UC_X86_REG_EIP)
            enc_offset = int.from_bytes(uc.mem_read(r_eip + INTR_OFFSET,1),'little')
            offset = enc_offset ^ KEY_OFFSET
            # print(f'EXCEPTION_SINGLE_STEP eip=0x{r_eip:X} offset=0x{offset:X}')
            uc.reg_write(UC_X86_REG_EIP, offset + r_eip)
            # clear the trap flag to continue execution
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~0x100)
            return True
        else:
            # print(f'Not 1 or 3 intno={intno}')
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

    #init registers
    mu.reg_write(UC_X86_REG_ESI, 0x10000)
    mu.reg_write(UC_X86_REG_EAX, 0x10000)
    mu.reg_write(UC_X86_REG_ECX, 0x10000)
    r_esp = mu.reg_read(UC_X86_REG_ESP)
    mu.mem_write(r_esp+4,struct.pack('<I',arg0_addr))   

    # tracing all instructions with customized callback
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # intercept invalid memory events
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED , hook_mem_invalid)
    mu.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_instruction_0)
    mu.hook_add(UC_HOOK_INTR, hook_intr)

    try:
        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32_SHELLCODE))
    except UcError as e:
        pass
        
    try:
    # read from memory arg0_addr which is the Arg0
        enc_blob_sz_b = mu.mem_read(arg0_addr, 4)
        enc_blob_sz = struct.unpack('I',enc_blob_sz_b)[0]
        if enc_blob_sz < 1000 and enc_blob_sz > 3:
            enc_blob_b = mu.mem_read(arg0_addr+4, enc_blob_sz)
            # print(f'EncSz = {enc_blob_sz} Encrypted Blob = {enc_blob_b.hex()}')
            return enc_blob_b
    except UcError as e:
        # print(">>> Failed to read enc config bytes")
        return None

def yara_matches(yara_file_name: str, target_dump: str) -> list[int]:
    try:
        rules = yara.compile(yara_file_name)
        with open(target_dump, 'rb') as file:
            matches = rules.match(data=file.read())
        
        return [instance.offset for match in matches for string in match.strings for instance in string.instances]
    except Exception as e:
        logger.error(f"Error in yara_matches: {e}")
        return []

def xor_decode(enc_b_data, key_b):
    key_b_len = len(key_b)
    return bytearray(x ^ key_b[i % key_b_len] for i, x in enumerate(enc_b_data))
    
def read_bytes(filename, offset, num_bytes):
    with open(filename, 'rb') as file:
        file.seek(offset)  # Move to the specified offset
        bytes_read = file.read(num_bytes)  # Read the specified number of bytes
    return bytes_read


def url_validator(input_string: str) -> Optional[str]:
    pattern = r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\/[a-zA-Z0-9\/_\-]+(\.[a-zA-Z0-9]+)?$"
    return input_string if re.match(pattern, input_string.rstrip('\x00')) else None

def main():
    yara_file_name = "guloader_shellcode_config.rules.yara"
    target_dump = "wab.exe.bin"
    SC_bytes_sz = 0x1500
    key_bytes = "367364158b08fd58be54ce47efd3843da8269c11780c3c330d643ec57896f0fb4e"
    key_b = bytes.fromhex(key_bytes)

    #locate all possible start of enc config functions
    file_offset_list = yara_matches(yara_file_name, target_dump)
    
    #start emulating enc config functions and decode enc config
    for file_offset in file_offset_list:
        SC_bytes = read_bytes(target_dump, file_offset, SC_bytes_sz)
        enc_b = emulator(SC_bytes)
        if enc_b is None:
            continue

        clr = xor_decode(enc_b, key_b)
        
        try:
            clr_str = clr.decode('utf-16') if b"\x00" in clr[:-1] else clr.decode()
        except UnicodeError:
            continue
        
        # Locate C2 Url
        url_found = url_validator(clr_str)
        if url_found:
            c2_url = f"{'https' if 's' in url_found[4] else 'http'}://{url_found[8 if 's' in url_found[4] else 7:]}"
            logger.info(f'C2 url = {c2_url} enc config addr = 0x{file_offset:X}')
            return
if __name__ == "__main__":
    main()