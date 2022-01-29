import struct
import io
import sys

import deflatedecompress as dd

class VoidStream:
    def __init__(self):
        self._count = 0
    def write(self,b):
        self._count += len(b)
    def write_unk(self):
        self._count += 1
    @property
    def count(self): return self._count

def findNextValidBlock(S, StartAt):
    CurIdx = StartAt
    S.seek(0, 2)
    Len = S.tell()
    while True:
        if CurIdx >= Len*8:
            return None
        if CurIdx & 1023 == 0:
            print("[/] Trying to decompress at index %d..." % CurIdx, "\r", end='')
            sys.stdout.flush()
        S.seek(CurIdx//8)
        BS = dd.BitInputStream(S)
        for _ in range(CurIdx&7): BS.read()
        CurIdx += 1
        try:
            Out = VoidStream()
            D = dd.Decompressor(BS, Out)
            D.readAll()
            if S.tell() < Len-16: continue
            print("")
            return (CurIdx-1,Out.count)
        except ValueError as e:
            pass
        except EOFError as e:
            pass

def decompressAt(S, Idx, Out):
    S.seek(Idx//8)
    BS = dd.BitInputStream(S)
    for _ in range(Idx&7): BS.read()
    dd.Decompressor(BS, Out).readAll()

if __name__ == "__main__":
    import sys
    S = open(sys.argv[1],"rb")
    S.seek(-8, 2)
    CRC, DecompSize = struct.unpack("<II", S.read(8))
    Idx, Len = findNextValidBlock(S, (10+6)*8)
    Out = open(sys.argv[2],"wb")
    Out.seek(DecompSize-Len)
    print("[+] Decompressing...")
    decompressAt(S, Idx, Out)
