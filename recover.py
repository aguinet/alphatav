import io
import struct
import zlib
import itertools
import datetime
import copy
import os
from rft import RFT,BitCount
from decrypt import GZipStream, GetSettings, DecryptImage, GetEncrAlgos, DecrStream, TimeKey, EncrAlgos, DotNetGetByName, GetFiles
import gz_recover

class EncodedData:
    def __init__(self, V):
        BC = BitCount(V)
        self.AT = (BC == 8) or (BC > 0 and BC <= 4)
        if V == 0xFF or V == 0:
            self.BS = 0
        else:
            self.BS = BC if self.AT else (8-BC)
        self.AI = 0
        if V != 0xFF and V != 0:
            for i in reversed(range(8)):
                b = (V >> i) & 1
                if (int(self.AT) == b):
                    self.AI = 10*self.AI + (7-i)

    def __repr__(self):
        return "AT=%d,BS=%d,AI=%d" % (self.AT,self.BS,self.AI)

SB = [0,1,2,3,4,5,6,7,12,13,14,15,16,17,23,24,25,26,27,34,35,36,37,45,46,47,56,57,67,123,124,125,126,127,134,135,136,137,145,146,147,156,157,167,234,235,236,237,245,246,247,256,257,267,345,346,347,356,357,367,456,457,467,567,1234,1235,1236,1237,1245,1246,1247,1256,1257,1267,1345,1346,1347,1356,1357,1367,1456,1457,1467,1567,2345,2346,2347,2356,2357,2367,2456,2457,2467,2567,3456,3457,3467,3567,4567]
SBInv = {v: i for i,v in enumerate(SB)}

class Recovery:
    def __init__(self, ATD, K1, K2, CDSStart, SizeFT, OneFile):
        self.ATD = ATD
        self.K1 = K1
        self.K2 = K2
        self.FT = RFT(SizeFT)
        self.CDSStart = CDSStart
        self.OneFile = OneFile

        if isinstance(ATD, FutureAESDecrypt):
            self.ATD = ATD.Decrypt(self.FT)

    @property
    def LenFT(self):
        return len(self.FT.ft)

    @property
    def LenData(self):
        return len(self.ATD)

    def GetClearBS(self, Off):
        Ret = self.K2[Off//2]
        if Ret is None:
            return None
        if Off & 1: Ret >>= 4
        return Ret & 0xF

    def GetClearAT(self, Off):
        BitIdx = 7-Off%8
        ATOff = Off//8
        if self.K1[ATOff] is None:
            return None
        ATBit = self.FT.GetBit(ATOff % self.LenFT, BitIdx)
        if ATBit is None:
            return None
        return ((self.K1[ATOff] >> BitIdx) & 1) ^ ATBit

    def has(self, n):
        return not isinstance(getattr(self, n), FutureAESDecrypt)

    def Decrypt(self, n):
        S = getattr(self, n)
        assert(isinstance(S, FutureAESDecrypt))
        Data = S.Decrypt(self.FT)
        if not Data is None:
            print("[+] New stream decrypted!")
            setattr(self, n, Data)
            return True
        return False

    def ClearByte(self, Off, V):
        OffFT = Off%self.LenFT
        ED = EncodedData(V)

        if self.has("K2"):
            Ref = self.GetClearBS(Off)
            if not Ref is None:
                if ED.BS != self.GetClearBS(Off):
                    raise ValueError("value not coherent with known block size!")

        # Known byte thanks to indexes
        if not self.ATD[Off] is None:
            self.FT.SetByte(OffFT, SBInv[ED.AI] ^ self.ATD[Off])
        
        if self.has("K1"): 
            # Know bit thanks to AlphaTav
            ATBit = 1 if ED.AT else 0
            BitIdx = 7-Off%8
            ATOff = Off//8
            if not self.K1[ATOff] is None:
                EncrATBit = (self.K1[ATOff] >> BitIdx) & 1
                self.FT.SetByteBit((Off//8)%self.LenFT, BitIdx, EncrATBit ^ ATBit)

    def ClearData(self, Off, PT):
        for I,V in enumerate(PT):
            self.ClearByte(Off+I, V)

    def Recover00FF(self):
        for I in range(self.LenData):
            BS = self.GetClearBS(I)
            if BS != 0:
                continue
            AT = self.GetClearAT(I)
            if AT is None:
                continue
            self.ClearByte(I, 0 if AT == 0 else 0xFF)

    def __call__(self):
        print("[/] First round...")
        self.RecoverAll()
        if self.FT.Full():
            return
        RB,P = self.FT.Stats()
        print("[/] First round finished, FT not full. Status: %0.4f %%" % (P*100.))
        Changed = False
        if not self.has("K1"):
            print("[/] Attempt to decrypt K1...")
            Changed |= self.Decrypt("K1")
        if not self.has("K2"):
            print("[/] Attempt to decrypt K2...")
            Changed |= self.Decrypt("K2")
        if Changed:
            print("[/] Going for another round!")
            self.RecoverAll()

    def RecoverAll(self):
        # First step is we know that the 8th bit of AT is always 0
        for I,V in enumerate(self.ATD):
            if V is None: continue
            # MSB bit is directly the bit of FT
            self.FT.SetByteBit(I%(self.LenFT),7,(V>>7)&1)

        RB,P = self.FT.Stats()
        print("[/] Factor table recovered: %d bits, %0.4f %%" % (RB,P*100.))

        # We know CDSStart, so that gives us other plain texts, *and* the length of the filename!
        self.ClearData(self.CDSStart, bytes.fromhex("504b0102"))#2d002d0009080800"))
        if self.OneFile:
            FileNameLength = len(self.ATD)-self.CDSStart-212
            print("[+] Filename length: %d" % FileNameLength)

        # Then, we know the header of PK
        self.ClearData(0, bytes.fromhex("504b03042d"))#0009080800"))
        self.ClearData(14, bytes.fromhex("00000000ffffffffffffffff"))
        if self.OneFile:
            self.ClearData(26, struct.pack("<H", FileNameLength))
        self.ClearData(28, struct.pack("<H", 56))

        # CDStart partial
        #self.ClearData(self.CDSStart + 30, bytes.fromhex("44000000000000008000000000000000"))

        # CompSize + OrgSize are both at 0xFFFFFFFF, then the FileNameLength and other data
        #self.ClearData(self.CDSStart + 20, b"\xFF\xFF\xFF\xFF"*2) 
        if self.OneFile:
            self.ClearData(self.CDSStart + 28, struct.pack("<HHHHHII", FileNameLength, 68, 0, 0, 0, 128, 0))

        # End of zip: CDSStart + CommentLength = 0
        EndZip = struct.pack("<I", self.CDSStart) + b"\x00"*2
        self.ClearData(len(self.ATD)-len(EndZip), EndZip)

        # End of zip: EOCD structure until CDSize
        EOCDStart = len(self.ATD)-22
        EndZip = b"PK\x05\x06\x00\x00\x00\x00\xFF\xFF\xFF\xFF"
        self.ClearData(EOCDStart, EndZip)

        # EOCD64Loc
        EOCD64LocStart = EOCDStart-20
        self.ClearData(EOCD64LocStart, bytes.fromhex("504b060700000000"))
        # DiskCount = 1
        self.ClearData(EOCD64LocStart+16, struct.pack("<I", 1))

        # EOCD64Record
        EOCD64RecordStart = EOCD64LocStart-56
        if self.OneFile:
            self.ClearData(EOCD64RecordStart, bytes.fromhex("504b06062c000000000000002d002d00000000000000000001000000000000000100000000000000"))
        self.ClearData(EOCD64RecordStart+48, struct.pack("<Q", self.CDSStart))

        RB,P = self.FT.Stats()
        print("[/] Factor table recovered: %d bits, %0.4f %%" % (RB,P*100.))

        if self.has("K1") and self.has("K2"):
            for i in range(1):
                print("[/] Recover zeros and FF...")
                self.Recover00FF()
                RB,P = self.FT.Stats()
                print("[/] Factor table recovered: %d bits, %0.4f %%" % (RB,P*100.))

def GetCDSStart(Settings2):
    return DotNetGetByName(Settings2, "<CDSStartPosition>k__BackingField", Settings2)

def BFByte(KnownValue, KnownMask):
    if KnownMask == 0xFF:
        yield KnownValue
        return
    KnownValue &= KnownMask
    for V in range(256):
        if (V & KnownMask) != KnownValue:
            continue
        yield V

def BFZlib(Stream, RFT, TimeKey):
    Data = bytearray(Stream.read())
    Known = RFT.recov_mask[10:16]

    if RFT.recov_mask[14] == 0xFF or RFT.recov_mask[15] == 0xFF:
        # Try with block type == 0
        Data[10] = 0
        # If we have [type == 0] [len 2 bytes] [~len 2 bytes], we known the
        # last byte of "~len", so one byte of len. So at most one byte to
        # bruteforce!
        CRC = struct.unpack("<I", Data[-8:-4])[0]
        Data[12] = (~Data[14]) & 0xFF
        for L0 in BFByte(Data[11], RFT.recov_mask[11]):
            NL0 = (~L0)&0xFF
            Data[11] = L0
            Data[13] = NL0
            try:
                Ret = zlib.decompress(Data[10:-8], -zlib.MAX_WBITS)
            except zlib.error as e:
                continue
            CurCRC = zlib.crc32(Ret)
            if CurCRC == CRC:
                print("[+] Found valid deflate stream!")
                return Ret
            else:
                print("[/] Bad CRC, going on...")

    print("[-] Unable to recover deflate stream!")
    return None
    
class FutureAESDecrypt:
    def __init__(self, Stream, TimeKey):
        self.Stream = Stream
        self.TimeKey = TimeKey
        self.RecovIdx = (10+6)*8
        self.Partial = None

    def Decrypt(self, RFT_):
        self.Stream.seek(0)
        Ret = DecrStream(self.Stream, bytes(RFT_.ft), self.TimeKey, 1) # 1 == AES
        if any(v != 0xFF for v in RFT_.recov_mask[10:16]):
            print("[-] Stream: unable to decrypt. Trying to bruteforce remaining bits...")
            BFRet = BFZlib(Ret, RFT_, self.TimeKey)
            if not BFRet is None:
                return BFRet
            print("[-] Didn't work. Decompressing what we can!")
            # Decompress what we can
            if not self.Partial is None:
                return self.Partial
            Ret.seek(-4, 2)
            DecSize = struct.unpack("<I", Ret.read(4))[0]
            Idx, PartialDecSize = gz_recover.findNextValidBlock(Ret, self.RecovIdx)
            self.RecovIdx = Idx
            print("[+] Partial decompressed stream can be recovered! Recovering...")
            class Writer:
                def __init__(self, unkHeader):
                    self.data = [None]*unkHeader
                def write(self, b):
                    self.data.extend(b)
                def write_unk(self):
                    self.data.append(None)
            Out = Writer(DecSize-PartialDecSize)
            gz_recover.decompressAt(Ret, Idx, Out)
            KnownBytes = sum(int(not V is None) for V in Out.data)
            print("[+] Recovered %d bytes over %d (%0.4f %%)" % (KnownBytes, DecSize, (float(KnownBytes)/float(DecSize))*100.))
            self.Partial = Out.data
            return Out.data
        Ret.seek(10)
        return GZipStream(io.BytesIO(b"\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\xFF" + Ret.read())).read()

def Decr(Stream, TimeKey, Algo):
    if Algo == 0:
        return Stream
    if Algo == 1: # AES
        return FutureAESDecrypt(Stream, TimeKey)

    else:
        assert(Algo in (2,3))
        Data = DecrStream(Stream, b"\x00"*16, TimeKey, Algo)
        KnownHeader = bytes.fromhex("1F8B0800")
        Data.seek(4)
        return io.BytesIO(KnownHeader + Data.read())

def GZipStreamRead(Stream):
    if not isinstance(Stream, FutureAESDecrypt):
        return GZipStream(Stream).read()
    return Stream

def GetStream(Path, TK, Algo):
    Cache = Path + ".decr"
    if os.path.exists(Cache):
        print("[+] Using cache file '%s'..." % Cache)
        return open(Cache,"rb").read()
    S = GZipStreamRead(Decr(open(Path, "rb"), TK, Algo))
    if not isinstance(S, FutureAESDecrypt):
        open(Cache, "wb").write(S)
    else:
        print("[/] Stream encrypted with AES. Postponing its decryption.")
    return S

def GetAlgoName(A):
    if A == 0:
        return "none"
    if A == 1:
        return "AES256"
    if A == 2:
        return "3DES"
    if A == 3:
        return "RC2"
    raise ValueError("unknown algo %d" % A)

def GetStreams(PathATD, PathK1, PathK2, PathK3):
    Settings = GetSettings(PathK3)
    print("[+] Get settings from %s..." % PathK3)
    Settings2 = DecryptImage(PathK3, Settings.TK.GetBytes(), Settings.TK, Settings.EncrAlgo3)

    Algos = GetEncrAlgos(Settings2)
    for F in ("ATD","K1","K2"):
        print("[+] Encryption algorithm for %s: %s" % (F, GetAlgoName(getattr(Algos, F))))

    print("[+] Decrypt and decompress ATD...")
    ATD = GetStream(PathATD, Settings.TK, Algos.ATD)
    print("[+] Decrypt and decompress K1...")
    K1  = GetStream(PathK1,  Settings.TK, Algos.K1)
    print("[+] Decrypt and decompress K2...")
    K2  = GetStream(PathK2,  Settings.TK, Algos.K2)

    return ATD, K1, K2, Settings2

def CheckFTLength(ATD, L):
    LAligned = min((len(ATD)//L)*L,1000*L)
    for I in range(0,LAligned-L,L):
        Diff = (a^b for a,b in zip(ATD[I:I+L],ATD[I+L:I+2*L]))
        if any((x>>7)&1 == 1 for x in Diff):
            return False
    return True

class Ref:
    def __init__(self, O):
        self.O = O

def FindFTLength(ATD):
    for L in range(10,1311):
        L *= 100
        L = max(L,1024)
        L = min(L, 131072)
        if isinstance(ATD, FutureAESDecrypt):
            yield L
        elif CheckFTLength(ATD,L):
            yield L

if __name__ == "__main__":
    import sys
    if len(sys.argv) <= 2:
        print("Usage: %s atd_file out_ft" % sys.argv[0])
        sys.exit(1)

    PathATD, PathK1, PathK2, PathK3 = GetFiles(sys.argv[1])
    ATD, K1, K2, Settings = GetStreams(PathATD, PathK1, PathK2, PathK3)

    R = None
    CDSStart = GetCDSStart(Settings)
    for L in FindFTLength(ATD):
        print("[+] Trying with L=%d" % L)
        R = Recovery(ATD,K1,K2,CDSStart,L, False)
        try:
            R()
            break
        except ValueError as e:
            print("[/] unable to recover: %s" % str(e))
        except zlib.error as e:
            print("[/] unable to recover (zlib): %s" % str(e))
    if R is None:
        print("[-] Fatal error: unable to find a valid factor table size!")
        sys.exit(1)
    print("[+] Found a valid password length: %d!" % L)
    RB,P = R.FT.Stats()
    print("[+] Factor table recovered: %d bits, %0.4f %%" % (RB,P*100.))
    if R.FT.Full():
        path = sys.argv[2]
        print("[+] Got full factor table!! Save it to %s!" % path)
        open(path,"wb").write(bytes(R.FT.ft))
