"""
IDA helper for IGS PGM BIOS analysis with verbose logging.
Run after loading the 68000 ROM at 0x000000.
"""

import idaapi
try:
    import ida_segment
except ImportError:
    import idaapi as ida_segment
try:
    import ida_bytes
except ImportError:
    import idaapi as ida_bytes
try:
    import ida_name
except ImportError:
    import idaapi as ida_name
try:
    import ida_enum
except ImportError:
    ida_enum = idaapi
try:
    import ida_idaapi
except ImportError:
    ida_idaapi = idaapi

BADADDR = getattr(ida_idaapi, "BADADDR", -1)
ADDSEG_NOSREG = getattr(ida_segment, "ADDSEG_NOSREG", 0)
SEGMOD_KEEP = getattr(ida_segment, "SEGMOD_KEEP", 0)
SEGMOD_SILENT = getattr(ida_segment, "SEGMOD_SILENT", 0x800)
SEGATTR_PERM = getattr(ida_segment, "SEGATTR_PERM", 7)
SEGPERM_READ = getattr(ida_segment, "SEGPERM_READ", 1)
SEGPERM_WRITE = getattr(ida_segment, "SEGPERM_WRITE", 2)
SEGPERM_EXEC = getattr(ida_segment, "SEGPERM_EXEC", 4)

SEGMENTS = [
    (0x000000, 0x100000, "PGM_BIOS", "CODE", SEGPERM_READ | SEGPERM_EXEC),
    (0x100000, 0x400000, "PGM_BANKROM", "DATA", SEGPERM_READ),
    (0x700000, 0x700010, "PGM_WATCHDOG", "IO", SEGPERM_READ | SEGPERM_WRITE),
    (0x800000, 0x820000, "PGM_SRAM", "DATA", SEGPERM_READ | SEGPERM_WRITE),
    (0x900000, 0x908000, "PGM_VRAM", "DATA", SEGPERM_READ | SEGPERM_WRITE),
    (0xa00000, 0xa01200, "PGM_PALETTE", "DATA", SEGPERM_READ | SEGPERM_WRITE),
    (0xb00000, 0xb10000, "PGM_VREG", "IO", SEGPERM_READ | SEGPERM_WRITE),
    (0xc00000, 0xc00010, "PGM_SOUNDPORT", "IO", SEGPERM_READ | SEGPERM_WRITE),
    (0xc08000, 0xc08008, "PGM_INPUTS", "IO", SEGPERM_READ | SEGPERM_WRITE),
    (0xc10000, 0xc20000, "PGM_Z80SHARE", "DATA", SEGPERM_READ | SEGPERM_WRITE),
]

IO_LABELS = {
    0x700006: ("pgm_watchdog_w", "Watchdog write (possible reset)"),
    0xc00003: ("pgm_m68k_to_z80", "Main CPU -> sound latch 1 (triggers Z80 NMI)"),
    0xc00005: ("pgm_m68k_to_z80_b", "Main CPU -> sound latch 2"),
    0xc00007: ("pgm_rtc", "V3021 real-time clock"),
    0xc00008: ("pgm_z80_reset", "Write 0x5050 to release Z80 + reset ICS2115"),
    0xc0000a: ("pgm_z80_ctrl", "Sound control / bank"),
    0xc0000d: ("pgm_z80_to_m68k", "Sound CPU -> main latch"),
    0xc08000: ("pgm_inputs_p1p2", "Inputs: P1/P2 start, joystick, buttons"),
    0xc08002: ("pgm_inputs_p3p4", "Inputs: P3/P4 controls"),
    0xc08004: ("pgm_inputs_service", "Service/test buttons, coin"),
    0xc08006: ("pgm_inputs_dsw", "DIP switch bank, also coin counter write"),
}

ENUMS = [
    {
        "name": "pgm_inputs_bits",
        "comment": "Input bit definitions (see pgm.cpp)",
        "values": [
            (0x0001, "START1"), (0x0002, "P1_UP"), (0x0004, "P1_DOWN"),
            (0x0008, "P1_LEFT"), (0x0010, "P1_RIGHT"), (0x0020, "P1_BUTTON1"),
            (0x0040, "P1_BUTTON2"), (0x0080, "P1_BUTTON3"), (0x0100, "START2"),
            (0x0200, "P2_UP"), (0x0400, "P2_DOWN"), (0x0800, "P2_LEFT"),
            (0x1000, "P2_RIGHT"), (0x2000, "P2_BUTTON1"), (0x4000, "P2_BUTTON2"),
            (0x8000, "P2_BUTTON3"),
        ],
    },
]


def log(msg):
    idaapi.msg("[PGM] %s\n" % msg)


def seg_name(seg):
    getter = getattr(ida_segment, "get_segm_name", getattr(idaapi, "get_segm_name", None))
    if getter:
        try:
            return getter(seg)
        except TypeError:
            return getter(seg.start_ea)
    return "?"


def seg_class(seg):
    getter = getattr(ida_segment, "get_segm_class", getattr(idaapi, "get_segm_class", None))
    if getter:
        try:
            return getter(seg)
        except TypeError:
            return getter(seg.start_ea)
    return "?"


def seg_perm(seg):
    return getattr(seg, "perm", 0)


def debug_segments(header):
    log("%s" % header)
    qty = getattr(ida_segment, "get_segm_qty", lambda: 0)()
    log("segments=%d" % qty)
    getnseg = getattr(ida_segment, "getnseg", getattr(idaapi, "getnseg", None))
    for i in range(qty):
        seg = getnseg(i)
        log("  #%d %s %06X-%06X class=%s perm=%d" % (
            i,
            seg_name(seg),
            seg.start_ea & 0xFFFFFF,
            seg.end_ea & 0xFFFFFF,
            seg_class(seg),
            seg_perm(seg)))


def set_segment_name(seg, name):
    setter = getattr(ida_segment, "set_segm_name", getattr(idaapi, "set_segment_name", None))
    if setter:
        try:
            setter(seg, name)
        except TypeError:
            setter(seg.start_ea, name)
        log("  set name -> %s" % name)


def set_segment_class(seg, sclass):
    setter = getattr(ida_segment, "set_segm_class", getattr(idaapi, "set_segment_class", None))
    if setter:
        try:
            setter(seg, sclass)
        except TypeError:
            setter(seg.start_ea, sclass)
        log("  set class -> %s" % sclass)


def set_segment_perm(seg, perm):
    setter = getattr(ida_segment, "set_segm_attr", getattr(idaapi, "set_segm_attr", None))
    if setter:
        setter(seg, SEGATTR_PERM, perm)
    else:
        seg.perm = perm
        ida_segment.update_segm(seg)
    log("  set perm -> %d" % perm)


def extend_segment(seg, end_ea):
    if seg.end_ea >= end_ea:
        return seg
    setter = getattr(ida_segment, "set_segm_end", getattr(idaapi, "set_segm_end", None))
    if setter:
        try:
            setter(seg, end_ea, SEGMOD_KEEP | SEGMOD_SILENT)
        except TypeError:
            setter(seg.start_ea, end_ea, SEGMOD_KEEP | SEGMOD_SILENT)
    log("  extend end -> %06X" % (end_ea & 0xFFFFFF))
    return ida_segment.getseg(seg.start_ea)


def find_segment_covering(addr):
    seg = ida_segment.getseg(addr)
    if seg and seg.start_ea <= addr < seg.end_ea:
        return seg
    getnseg = getattr(ida_segment, "getnseg", getattr(idaapi, "getnseg", None))
    qty = getattr(ida_segment, "get_segm_qty", lambda: 0)()
    for i in range(qty):
        seg = getnseg(i)
        if seg.start_ea <= addr < seg.end_ea:
            return seg
    return None


def ensure_segment(start, end, name, sclass, perm):
    log("ensure %s %06X-%06X" % (name, start & 0xFFFFFF, end & 0xFFFFFF))
    seg = find_segment_covering(start)
    if seg and seg.start_ea == start:
        log("  exact match %s" % seg_name(seg))
        if seg.end_ea < end:
            seg = extend_segment(seg, end)
        set_segment_name(seg, name)
        set_segment_class(seg, sclass)
        set_segment_perm(seg, perm)
        return
    if seg:
        log("  start inside %s" % seg_name(seg))
        setter = getattr(ida_segment, "set_segm_start", getattr(idaapi, "set_segm_start", None))
        if setter and seg.start_ea != start:
            try:
                setter(seg, start, SEGMOD_KEEP | SEGMOD_SILENT)
            except TypeError:
                setter(seg.start_ea, start, SEGMOD_KEEP | SEGMOD_SILENT)
            seg = ida_segment.getseg(start)
        if seg.end_ea < end:
            seg = extend_segment(seg, end)
        set_segment_name(seg, name)
        set_segment_class(seg, sclass)
        set_segment_perm(seg, perm)
        return
    log("  creating")
    seg_t = ida_segment.segment_t()
    seg_t.start_ea = start
    seg_t.end_ea = end
    seg_t.sel = 0
    seg_t.bitness = 1
    seg_t.perm = perm
    add_ex = getattr(ida_segment, "add_segm_ex", None)
    if add_ex:
        add_ex(seg_t, name, sclass, ADDSEG_NOSREG)
    else:
        ida_segment.add_segm(start, end, name, sclass)
    seg = find_segment_covering(start)
    if seg:
        set_segment_name(seg, name)
        set_segment_class(seg, sclass)
        set_segment_perm(seg, perm)


def define_segments():
    debug_segments("Before segment pass")
    for start, end, name, sclass, perm in SEGMENTS:
        ensure_segment(start, end, name, sclass, perm)
    debug_segments("After segment pass")


def define_io_labels(labels):
    log("Assigning IO labels")
    for addr, (name, cmt) in sorted(labels.items()):
        seg = find_segment_covering(addr)
        if seg is None:
            log("  skip %s at %06X (no segment)" % (name, addr & 0xFFFFFF))
            continue
        ida_name.set_name(addr, name, ida_name.SN_FORCE | ida_name.SN_PUBLIC)
        log("  label %06X -> %s" % (addr & 0xFFFFFF, name))
        setter = getattr(ida_bytes, "set_cmt", getattr(idaapi, "make_cmt", None))
        if cmt and setter:
            try:
                setter(addr, cmt, False)
            except TypeError:
                setter(addr, cmt)


def get_enum(name):
    for module in (ida_enum, idaapi):
        getter = getattr(module, "get_enum", None)
        if getter:
            try:
                enum_id = getter(name)
            except TypeError:
                enum_id = getter(name, -1)
            if enum_id not in (None, BADADDR, 0xFFFFFFFF):
                return enum_id
        getter = getattr(module, "get_enum_by_name", None)
        if getter:
            enum_id = getter(name)
            if enum_id not in (None, BADADDR, 0xFFFFFFFF):
                return enum_id
    return BADADDR


def add_enum(name):
    for module in (ida_enum, idaapi):
        creator = getattr(module, "add_enum", None)
        if creator:
            try:
                enum_id = creator(BADADDR, name, getattr(module, "hexadecimal", 0x1100))
            except TypeError:
                enum_id = creator(-1, name, getattr(module, "hexadecimal", 0x1100))
            if enum_id not in (None, BADADDR, 0xFFFFFFFF):
                return enum_id
    return BADADDR


def create_enums():
    log("Ensuring enums")
    add_member = getattr(ida_enum, "add_enum_member", getattr(idaapi, "add_enum_member", None))
    get_member = getattr(ida_enum, "get_enum_member_by_value", getattr(idaapi, "get_enum_member_by_value", None))
    set_cmt = getattr(ida_enum, "set_enum_cmt", getattr(idaapi, "set_enum_cmt", None))
    for enum_def in ENUMS:
        name = enum_def["name"]
        enum_id = get_enum(name)
        if enum_id in (None, BADADDR, 0xFFFFFFFF):
            enum_id = add_enum(name)
            log("  created enum %s -> %s" % (name, hex(enum_id & 0xFFFFFFFF)))
        else:
            log("  enum %s already exists" % name)
        if enum_id in (None, BADADDR, 0xFFFFFFFF):
            continue
        comment = enum_def.get("comment")
        if comment and set_cmt:
            try:
                set_cmt(enum_id, comment, False)
            except TypeError:
                set_cmt(enum_id, comment, 0)
        if not add_member or not get_member:
            continue
        for value, label in enum_def["values"]:
            try:
                existing = get_member(enum_id, value, BADADDR)
            except TypeError:
                existing = get_member(enum_id, value)
            if existing not in (None, BADADDR, 0xFFFFFFFF):
                continue
            add_member(enum_id, label, value)
            log("    add %s = %04X" % (label, value))


def run():
    define_segments()
    define_io_labels(IO_LABELS)
    create_enums()
    log("Done")


if __name__ == "__main__":
    run()
