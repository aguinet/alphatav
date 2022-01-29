def BitCount(V):
    Ret = 0
    while V > 0:
        Ret += V&1
        V >>= 1
    return Ret

class RFT:
    def __init__(self, size_bytes):
        self.recov_mask = [0]*size_bytes
        self.ft = [0]*size_bytes

    def _check_val(self, new, old):
        if new != old:
            raise ValueError("setting a value different from what was previously known")

    def GetBit(self, idx_byte, idx_bit):
        if self.IsBitKnown(idx_byte, idx_bit):
            return (self.ft[idx_byte] >> idx_bit) & 1
        return None

    def IsBitKnown(self, idx_byte, idx_bit):
        assert(idx_bit <= 7)
        return ((self.recov_mask[idx_byte] >> idx_bit) & 1) == 1

    def SetByteBit(self, idx_byte, idx_bit, v):
        assert(idx_bit <= 7)
        kb = self.GetBit(idx_byte, idx_bit)
        if not kb is None:
            self._check_val(v, kb)
            return
        self.ft[idx_byte] |= (v << idx_bit)
        self.recov_mask[idx_byte] |= (1 << idx_bit)

    def SetByte(self, idx_byte, v):
        assert(v <= 0xFF)
        rm = self.recov_mask[idx_byte]
        if rm == 0xFF:
            self._check_val(v, self.ft[idx_byte])
            return
        if rm == 0:
            self.ft[idx_byte] = v
            self.recov_mask[idx_byte] = 0xFF
            return
        for i in range(8):
            self.SetByteBit(idx_byte, i, (v >> i) & 1)

    def SetByteLow4Bits(self, idx_byte, v):
        assert(v <= 0xF)
        rm = self.recov_mask[idx_byte]
        cur_ft = self.ft[idx_byte]
        if (rm == 0xFF):
            self._check_val(v, cur_ft & 0xF)
            return
        if (rm == 0):
            self.ft[idx_byte] = v
            self.recov_mask[idx_byte] = 0xF
            return
        for i in range(4):
            self.SetByteBit(idx_byte, i, (v >> i) & 1)

    def SetByteHigh4Bits(self, idx_byte, v):
        assert(v <= 0xF)
        rm = self.recov_mask[idx_byte]
        cur_ft = self.ft[idx_byte]
        if (rm == 0xFF):
            self._check_val(v, (cur_ft >> 4) & 0xF)
            return
        if (rm == 0):
            self.ft[idx_byte] = v<<4
            self.recov_mask[idx_byte] = 0xF0
            return
        for i in range(4):
            self.SetByteBit(idx_byte, i+4, (v >> i) & 1)

    def checkWithRef(self, Ref):
        assert(len(self.ft) == len(Ref))
        for Mask,V,R in zip(self.recov_mask, self.ft, Ref):
            #print(hex(Mask),hex(V),hex(R))
            assert(V&Mask == R&Mask)

    def Stats(self):
        KnownBits = sum(BitCount(v) for v in self.recov_mask)
        return KnownBits,float(KnownBits)/float(8*len(self.ft))

    def Full(self):
        return all(v == 0xFF for v in self.recov_mask)

if __name__ == "__main__":
    O = RFT(4)
    O.SetByte(0, 0xAB)
    O.SetByte(0, 0xAB)
    try:
        O.SetByte(0, 0xAA)
        sys.exit(1)
    except ValueError: pass
    O.SetByteBit(0, 1, 1)
    try:
        O.SetByteBit(0, 1, 0)
        sys.exit(1)
    except ValueError: pass
    O.SetByteLow4Bits(0, 0xB)
    try:
        O.SetByteLow4Bits(0, 0xF)
        sys.exit(1)
    except ValueError: pass
    O.SetByteHigh4Bits(0, 0xA)
    try:
        O.SetByteHigh4Bits(0, 0xF)
        sys.exit(1)
    except ValueError: pass
    O.SetByteBit(1,1,1)
    try:
        O.SetByte(1, 0x9)
        sys.exit(1)
    except ValueError: pass
    O.SetByte(1, 0xB)
