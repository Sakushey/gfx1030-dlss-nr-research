import sys
sys.path.insert(0, '.')
from emu import Core, Halt, build_orig_program
import eightbk as B

mem, ptrs = B.make_mem(split_count=0, hidden_3c=0)
core = Core(B.prog_orig, lanes=32, wavebase=0, mem=mem)
core.s[0] = 0x10000
core.s[1] = 0
core.s[14] = 0
core.s[15] = 0
try:
    for _ in range(400):
        pc = core.pc
        ins = B.prog_orig[pc]
        if core.steps < 90 or core.steps % 25 == 0:
            print(f"{core.steps:5d} pc={ins['address']:#08x} {ins['text'][:64]:<66} "
                  f"exec={core.exec_l:08x} vcc={core.vcc_l:08x} scc={core.scc} "
                  f"s4={core.s[4]:08x} s18={core.s[18]:08x} s16={core.s[16]:08x}", flush=True)
        core.step()
except Halt as h:
    print('HALT', h)
except Exception as e:
    import traceback
    traceback.print_exc()
    print('pc was', hex(B.prog_orig[core.pc]['address']), B.prog_orig[core.pc]['text'])
