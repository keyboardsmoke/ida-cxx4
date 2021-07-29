# This was partially made referencing Igor Skochinsky's gcc_extab.py
# Which I have updated to support modern IDA apis here:
# https://github.com/keyboardsmoke/recon-2012-skochinsky-scripts/blob/master/gcc_extab.py

IS64 = idaapi.getseg(here()).bitness == 2

IMAGEBASE = ida_nalt.get_imagebase()

# Unwind info definitions
UNW_FLAG_NHANDLER = 0
UNW_FLAG_EHANDLER = 1
UNW_FLAG_UHANDLER = 2
UNW_FLAG_CHAININFO = 4
UNW_FLAG_NO_EPILOGUE = 0x80000000 # Software only flag
UNWIND_CHAIN_LIMIT = 32

# From MS CRT
negLengthTab = [
    -1, # 0
    -2, # 1
    -1, # 2
    -3, # 3

    -1, # 4
    -2, # 5
    -1, # 6
    -4, # 7

    -1, # 8
    -2, # 9
    -1, # 10
    -3, # 11

    -1, # 12
    -2, # 13
    -1, # 14
    -5, # 15
]

shiftTab = [
    32 - 7 * 1, # 0
    32 - 7 * 2, # 1
    32 - 7 * 1, # 2
    32 - 7 * 3, # 3

    32 - 7 * 1, # 4
    32 - 7 * 2, # 5
    32 - 7 * 1, # 6
    32 - 7 * 4, # 7

    32 - 7 * 1, # 8
    32 - 7 * 2, # 9
    32 - 7 * 1, # 10
    32 - 7 * 3, # 11

    32 - 7 * 1, # 12
    32 - 7 * 2, # 13
    32 - 7 * 1, # 14
    0,          # 15
]

currentEa = 0

def read_byte():
    global currentEa
    val = get_original_byte(currentEa)
    currentEa += 1
    return val

def read_dword():
    global currentEa
    val = get_wide_dword(currentEa)
    currentEa += 4
    return val

def get_bit_num(num, pos, size):
    num >>= pos
    num &= ((1 << size) - 1)
    return num

def read_cxx4():
    global currentEa
    print("startPos = {:X}".format(currentEa))
    lengthByte = get_original_byte(currentEa)
    lengthBits = lengthByte & 0x0f
    negLength = negLengthTab[lengthBits]
    shift = shiftTab[lengthBits]
    print("lengthByte = {:X}, lengthBits = {:X}, negLength = {:X}, shift = {:X}".format(lengthByte, lengthBits, negLength, shift))
    readPos = (currentEa - negLength) - 4
    print("readPos = {:X}".format(readPos))
    result = get_wide_dword(readPos)
    print("result = {:X}".format(result))
    result >>= shift
    length = ((~(negLength)) + 1)
    print("length = {:X}".format(length))
    currentEa += length
    return result

def ForceWord(ea):
    if ea != BADADDR and ea != 0:
        if not is_word(get_full_flags(ea)) or get_item_end(ea) != 2:
            del_items(ea, 2, DELIT_SIMPLE)
            create_word(ea)
        if is_off0(get_full_flags(ea)) and GetFixupTgtType(ea) == -1:
            # remove the offset
            OpHex(ea, 0)
    
def ForceDword(ea):
    if ea != BADADDR and ea != 0:
        if not is_dword(get_full_flags(ea)) or get_item_end(ea) != 4:
            del_items(ea, 4, DELIT_SIMPLE)
            create_dword(ea)
        if is_off0(get_full_flags(ea)) and GetFixupTgtType(ea) == -1:
            # remove the offset
            OpHex(ea, 0)

def ForceQword(ea):
    if ea != BADADDR and ea != 0:
        if not is_qword(get_full_flags(ea)) or get_item_end(ea) != 8:
            del_items(ea, 8, DELIT_SIMPLE)
            create_qword(ea)
        if is_off0(get_full_flags(ea)) and GetFixupTgtType(ea) == -1:
            # remove the offset
            OpHex(ea, 0)

def ForcePtr(ea, delta = 0):
    if IS64:
        ForceQword(ea)
    else:
        ForceDword(ea)
    if GetFixupTgtType(ea) != -1 and is_off0(get_full_flags(ea)):
        # don't touch fixups
        return
    pv = ptrval(ea)
    if pv != 0 and pv != BADADDR:
        # apply offset again
        if idaapi.is_spec_ea(pv):
            delta = 0
        OpOffEx(ea, 0, [REF_OFF32, REF_OFF64][IS64], -1, 0, delta)

def make_reloff(ea, base, subtract = False):
    f = get_full_flags(ea)
    if is_byte(f) and get_item_end(ea) == 1 or \
        is_word(f) and get_item_end(ea) == 2 or \
        is_dword(f) and get_item_end(ea) == 4 or \
        is_qword(f) and get_item_end(ea) == 8:
        ri = idaapi.refinfo_t()
        flag = REF_OFF32|REFINFO_NOBASE
        if subtract:
            flag |= idaapi.REFINFO_SUBTRACT
        ri.init(flag, base)
        idaapi.op_offset_ex(ea, 0, ri)

def make_rel32():
    del_items(currentEa, 4, DELIT_SIMPLE)
    ri = idaapi.refinfo_t()
    ri.target = IMAGEBASE + get_wide_dword(currentEa)
    ri.base = IMAGEBASE
    ri.tdelta = 0

    ri.flags = REF_OFF32 | REFINFO_NOBASE

    idaapi.op_offset_ex(currentEa, 0, ri)

def format_byte(ea, cmt = None):
    if ea != BADADDR and ea != 0:
        if not is_byte(get_full_flags(ea)) or get_item_end(ea) != 1:
            del_items(ea, 1, DELIT_SIMPLE)
            create_byte(ea)
    if cmt:
        set_cmt(ea, cmt, False)
    return get_original_byte(ea)

def format_dword(ea, cmt = None):
    ForceDword(ea)
    if cmt:
        set_cmt(ea, cmt, False)
    return get_wide_dword(ea), ea + 4

def format_bbt():
    global currentEa
    bbtEa = currentEa
    bbt = read_cxx4()
    set_cmt(bbtEa, "BBT Value = {X:}".format(bbt), False)

def format_unwindmap():
    global currentEa
    startEa = currentEa
    unwindCount = read_cxx4()
    print("Unwind Count {:X} = {:X} -> {:X}".format(startEa, unwindCount, currentEa))

def format_cxx4_data():
    global currentEa
    print("CXX4 data = {:X}".format(currentEa))
    #set_name(currentEa, "", 0)
    currentEa = IMAGEBASE + read_dword()
    headerEa = currentEa
    header = read_byte()
    isCatch = get_bit_num(header, 0, 1)
    isSeperated = get_bit_num(header, 1, 1)
    BBT = get_bit_num(header, 2, 1)
    UnwindMap = get_bit_num(header, 3, 1)
    TryBlockMap = get_bit_num(header, 4, 1)
    EHs = get_bit_num(header, 5, 1)
    NoExcept = get_bit_num(header, 6, 1)
    set_cmt(headerEa, "isCatch {}, isSeperated {}, BBT {}, Unwind {}, TryBlock {}, EHs {}, NoExcept {}".format(isCatch, isSeperated, BBT, UnwindMap, TryBlockMap, EHs, NoExcept), False)

    dispUnwindMap = None
    dispTryBlockMap = None
    dispIPtoStateMap = None

    if (BBT == 1):
        format_bbt()
    if (UnwindMap == 1):
        set_cmt(currentEa, "dispUnwindMap", False)
        make_rel32()
        dispUnwindMap = IMAGEBASE + read_dword()
    if (TryBlockMap == 1):
        set_cmt(currentEa, "dispTryBlockMap", False)
        make_rel32()
        dispTryBlockMap = IMAGEBASE + read_dword()
    if (isSeperated == 1):
        raise Exception("Seperated IP to State maps are not supported")
    else:
        set_cmt(currentEa, "dispIPtoStateMap", False)
        make_rel32()
        dispIPtoStateMap = IMAGEBASE + read_dword()
    if (isCatch == 1):
        set_cmt(currentEa, "dispFrame", False)

    if dispUnwindMap != None:
        currentEa = dispUnwindMap
        format_unwindmap()

def format_unwind_data():
    global currentEa
    # print("unwind data = {:X}".format(currentEa))
    versionFlags = read_byte()
    sizeOfProlog = read_byte()
    countOfCodes = read_byte()
    frameRegisterAndOffset = read_byte()

    # Codes are 2 bytes, so if there is an odd number the linker will pad it to align it
    # Use alignedCount when calculating address of data that follows
    alignedCountOfCodes = ((countOfCodes + 1) & (~1))
    endOfCodes = currentEa + (alignedCountOfCodes * 2) # sizeof(uint16)
    currentEa = endOfCodes # we don't actually have to parse the codes

    flags = get_bit_num(versionFlags, 3, 5)

    if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)):
        handlerRvaEa = currentEa
        handlerRva = IMAGEBASE + read_dword()
        handlerName = get_func_name(handlerRva)
        if handlerName in ["__CxxFrameHandler4", "__GSHandlerCheck_EH4"]:
            print("HandlerName at {:X} {:X} = {}".format(handlerRvaEa, handlerRva, handlerName))
            format_cxx4_data()

def format_runtime_fn():
    global currentEa
    # print("RUNTIME_FN = {:X}".format(currentEa))
    beginAddress = read_dword()
    endAddress = read_dword()
    unwindAddress = read_dword()
    resumeEa = currentEa
    if beginAddress != 0 and beginAddress != 0xffffffff and endAddress != 0 and endAddress != 0xffffffff and unwindAddress != 0 and unwindAddress != 0xffffffff:
        currentEa = IMAGEBASE + unwindAddress
        format_unwind_data()

    currentEa = resumeEa

s = get_first_seg()
while s != BADADDR:
    if get_segm_name(s) in [".pdata"]:
        break
    s = get_next_seg(s)

if s != BADADDR:
    currentEa = get_segm_start(s)
    print("SEG {:X}".format(currentEa))
    endea = get_segm_end(s)
    while currentEa != BADADDR and currentEa < endea:
        format_runtime_fn()

print("CXX4 analysis finished")
