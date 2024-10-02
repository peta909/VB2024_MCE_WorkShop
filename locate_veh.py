#locate VEH while debugging using IDAPython
#make sure symbols are loaded for NTdll.dll as the names are from symbols
#Win 10.0.19045 Pro Build 19045 

 
# struct _LdrpVectorHandlerList
# {
#     SRWLOCK srw_lock; 
#     _LdrpVectorHandlerEntry* first;
#     _LdrpVectorHandlerEntry* last;
# };

# struct _LdrpVectorHandlerEntry
# {
#     _LdrpVectorHandlerEntry* flink;
#     _LdrpVectorHandlerEntry* blink;
#     DWORD pNumofVEH;
#     DWORD unknown2; #seems to be always 0
#     PVECTORED_EXCEPTION_HANDLER exception_handler;  <- THE GOAL!
# };

a=0
ror = lambda val, r_bits, max_bits: \
    ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))
    
#Locating the enc_veh    
ldrpvectorhandlerlist = idaapi.get_name_ea(a,"_LdrpVectorHandlerList")
ldrpvectorhandlerlistentry = idaapi.get_dword(ldrpvectorhandlerlist +4) 
enc_veh = idaapi.get_dword(ldrpvectorhandlerlistentry + 0x10)

#read cookie value
o_cookie = idaapi.get_name_ea(a,"?CookieValue@?1??RtlpGetCookieValue@@9@9")
o_cookie = idaapi.get_dword(o_cookie)

#Decoding the enc_veh
value = enc_veh
i = (32 - (o_cookie & 0x1F)) #no. of bits to rotate
max_bits = 32  # buffer size
ror_val =  ror(value, i, max_bits)
xored = ror_val ^ o_cookie
print(f'cookie::0x{o_cookie:X} enc_veh::0x{enc_veh:X} clr_veh::0x{xored:X}')

