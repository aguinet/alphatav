import struct
import zipfile
import base64
import hexdump
from PIL import Image
from PIL.TiffTags import TAGS
import construct
import dotnetDeser
import collections
import math
import functools
import operator
import gzip
import io
import os
import hashlib
from Crypto.Cipher import AES,DES3
import rc2

ENTRY_POINT_FACTOR_TABLE = [1,3,7,6,4,9,1,3,7,6]

def custom_b64dec(data, key):
    # Convert.FromBase64String(data.Remove(data.Length - 1, 1)).Xorify(key)
    data = base64.b64decode(data)
    return bytes(data[i]^key[i%len(key)] for i in range(len(data)))

def get_property(img, id_):
    return img.tag[id_][0]

def GetSettings(path):
    # From https://docs.microsoft.com/fr-fr/dotnet/api/system.drawing.imaging.propertyitem.id?view=netframework-4.8#System_Drawing_Imaging_PropertyItem_Id
    # 0x8298 	PropertyTagCopyright
    img = Image.open(path)
    settings = get_property(img, 33432)
    return DecodeSettings(settings)

def DecodePin(p):
    p = p.replace("_","/").replace("-","+")
    p += "=="
    return base64.b64decode(p)

TimeKey = collections.namedtuple("TimeKey", ("Factor","Gaps"))
Settings = collections.namedtuple("Settings", ("TK", "SecLevel", "EncrAlgo3"))

DefaultTK = TimeKey(Factor=3114301771477182624786406082198331742965222356897608094432720023397670845446982363566121170190763510107642915024024156614957784203, Gaps=[10,50,26,12,70,6,90])

def GetZipPassword(TK):
    # This is TK.Factor in base 8
    Factor = TK.Factor
    ret = ""
    while Factor > 0:
        ret += str(Factor & 7)
        Factor >>= 3
    return ret[::-1]

def TimeKey_GetBytes(self):
    F = hex(self.Factor)[2:].encode("ascii")
    Ret = F + struct.pack("<"+"H"*len(self.Gaps), *self.Gaps)
    return Ret

TimeKey.GetBytes = TimeKey_GetBytes

def DotNetGetByName(Obj, Name, Root):
    # Inefficient as hell but works for our needs
    Name = Name.encode("utf8")
    Ret = None
    for R in Obj:
        if not hasattr(R, "Obj"): continue
        R = R.Obj
        if not hasattr(R, "ClassInfo"): continue
        CI = R.ClassInfo
        try:
            Idx = next(i for i,v in enumerate(CI.MemberNames) if v.data == Name)
        except StopIteration: continue
        Ret = R.Values[Idx]
        break
    if Ret is None: return None
    if not hasattr(Ret, "RecordTypeEnum"): return Ret
    if Ret.RecordTypeEnum != dotnetDeser.RecordTypeEnum.MemberReference:
        return Ret
    # In case we have a reference, we have to go through the original object to find it!
    RefId = Ret.Obj.IdRef
    for R in Root:
        if not hasattr(R, "Obj"): continue
        O = R.Obj
        if hasattr(O, "ClassInfo"):
            if O.ClassInfo.ObjectId == RefId:
                return R
        if hasattr(O, "ArrayInfo"):
            if O.ArrayInfo.ObjectId == RefId:
                return R
    return None

def DecodeSettings(data):
    data = custom_b64dec(data, ENTRY_POINT_FACTOR_TABLE)
    data = deserialize(data)

    TK = DotNetGetByName(data, "<TimeKey>k__BackingField", data)
    Factor = DotNetGetByName([TK], "<Factor>k__BackingField", data)
    Gaps = DotNetGetByName([TK], "<Gaps>k__BackingField", data)
    Gaps = DotNetGetByName([Gaps], "buffer", data)
    
    Factor = int(Factor.Obj.Values[0].Obj.Value.data)
    Gaps = list(Gaps.Obj.Values)
    TK = TimeKey(Factor, Gaps)

    SecurityLevel = DotNetGetByName(data, "<SecurityLevel>k__BackingField", data)
    SecurityLevel = SecurityLevel.Obj.Values[0]

    EncryptionAlgorithmKey3 = DotNetGetByName(data, "<EncryptionAlgorithmKey3>k__BackingField", data)
    EncryptionAlgorithmKey3 = EncryptionAlgorithmKey3.Obj.Values[0]

    return Settings(TK, SecurityLevel, EncryptionAlgorithmKey3)


construct.lib.setGlobalPrintFullStrings(True)

def deserialize(data):
    all_ = dotnetDeser.parse(data) 
    return all_

TimeFactor = collections.namedtuple("TimeFactor", ("NearestPrime", "Value", "FactorIdx"))

def DecryptImage(PathK3, XorKey, TK, EncrAlgo):
    img = Image.open(PathK3)
    idx = 0
    ret = []
    for i in range(img.height):
        for j in range(img.width):
            c = img.getpixel((j,i))
            b = c[1] # (R,G,B,A)
            b ^= XorKey[idx % (len(XorKey))]
            ret.append(b)
            idx += 1
    ret = bytes(ret)
    if len(ret)%16 != 0:
        ret = ret[:-(len(ret)%16)]

    ret = DecrStream(io.BytesIO(ret), XorKey, DefaultTK, EncrAlgo, False).read()
    ret = dotnetDeser.parse(ret)
    return ret

def GZipStream(Stream):
    print("[+] GZip header:")
    hexdump.hexdump(Stream.read(32))
    Stream.seek(0)
    return gzip.GzipFile(fileobj=Stream,mode='rb')

def DecrStream(Stream, FT, TimeKey, Algo, unpad=True):
    if Algo == 0: # None
        return Stream
    TKBytes = TimeKey.GetBytes()
    if Algo == 1: # AES256
        IV = FT[:16]
        Key = TKBytes[:32]
        C = AES.new(Key, AES.MODE_CBC, IV)
        Decr = C.decrypt
    if Algo == 2: # TripleDES
        IV = FT[:8]
        Key = TKBytes[:24]
        C = DES3.new(Key, AES.MODE_CBC, IV)
        Decr = C.decrypt
    if Algo == 3: # RC2
        IV = FT[:8]
        Key = TKBytes[:16]
        C = rc2.RC2(Key)
        Decr = lambda Data: C.decrypt(Data, rc2.MODE_CBC, IV)
    Data = Decr(Stream.read())
    if unpad:
        Data = Data[:-Data[-1]]
    return io.BytesIO(Data)

class BlockSizeStream:
    def __init__(self, Stream):
        self._S = Stream

    def read(self, size):
        # This basically reads 4 bits by 4 bits
        NBytesToRead = (size + 1) >> 1
        Idx = 0
        for _ in range(NBytesToRead):
            if Idx >= size: break
            v = self._S.read(1)[0]
            c = v & 0xF
            yield c
            Idx += 1
            if Idx >= size: break
            c = (v >> 4) & 0xF
            yield c
            Idx += 1

class AlphaTavIndexesReader:
    SB = [0,1,2,3,4,5,6,7,12,13,14,15,16,17,23,24,25,26,27,34,35,36,37,45,46,47,56,57,67,123,124,125,126,127,134,135,136,137,145,146,147,156,157,167,234,235,236,237,245,246,247,256,257,267,345,346,347,356,357,367,456,457,467,567,1234,1235,1236,1237,1245,1246,1247,1256,1257,1267,1345,1346,1347,1356,1357,1367,1456,1457,1467,1567,2345,2346,2347,2356,2357,2367,2456,2457,2467,2567,3456,3457,3467,3567,4567]

    def __init__(self, Stream, FactorTable):
        self._S = Stream
        self._FT = FactorTable

    def read(self, size):
        for i in range(size):
            v = self._S.read(1)[0]
            yield self.SB[v^self._FT[i%len(self._FT)]]

class AlphaTavTableReader:
    def __init__(self, Stream, FT):
        self._S = Stream
        self._FT = FT

    def read(self, Size):
        SizeBlock = (Size+7)//8
        Idx = 0
        for i in range(SizeBlock):
            v = self._S.read(1)[0]
            v ^= self._FT[i%len(self._FT)]
            for b in reversed(range(8)):
                if i >= Size: return
                yield ((v >> b) & 1)
                i += 1

def Decode(AT, AI, BS):
    if (BS == 0):
        return 0 if AT == 0 else 0xFF
    b = 0
    if AT == 1 and AI == 0:
        return 128
    c = 0
    AI_ = AI
    while AI > 0:
        BI = abs(7-AI%10)
        b |= 1<<BI
        AI = AI//10
        c += 1
    if c < BS:
        b |= 128
    return b if (AT == 1) else ((~b) & 0xFF)

def GetStream(Path, FT, TK, Algo):
    Cache = Path + ".decr_real"
    if os.path.exists(Cache):
        print("[+] Using cache file '%s'..." % Cache)
        return open(Cache,"rb")
    S = GZipStream(DecrStream(open(Path, "rb"), FT, TK, Algo))
    open(Cache, "wb").write(S.read())
    del S
    return open(Cache,"rb")

def DecryptWithFT(PathATD, PathK1, PathK2, Settings, FactorTable, Algos):
    ATDStream = GetStream(PathATD, FactorTable, Settings.TK, Algos.ATD)
    ATDStream.seek(0, os.SEEK_END)
    Len = ATDStream.tell()
    ATDStream.seek(0, os.SEEK_SET)

    print("[+] Decrypting and decompressing streams...")
    AlphaIdxesStream = AlphaTavIndexesReader(ATDStream, FactorTable)
    AlphaIdxes = AlphaIdxesStream.read(Len)
    del ATDStream

    BlockSizeS = BlockSizeStream(GetStream(PathK2, FactorTable, Settings.TK, Algos.K2))
    BlockSizes = BlockSizeS.read(Len)

    AlphaTableStream = AlphaTavTableReader(GetStream(PathK1, FactorTable, Settings.TK, Algos.K1), FactorTable)
    Alphas = AlphaTableStream.read(Len)

    Buf = (Decode(AT, AI, BS) for BS,AI,AT in zip(BlockSizes, AlphaIdxes, Alphas))

    ZipPassword = GetZipPassword(Settings.TK)
    return Buf,ZipPassword

class EncrAlgos:
    def __init__(self, ATD, K1, K2):
        self.ATD = ATD
        self.K1  = K1
        self.K2  = K2

    @property
    def hasEncrypted(self):
        return any(v != 0 for v in (self.ATD, self.K1, self.K2))

    def withRC2or3DES(self):
        Algos = (2,3)
        if self.AATD in Algos:
            return "ATD"
        if self.AK1 in Algos:
            return "K1"
        if self.AK2 in Algos:
            return "K2"
        return None

def GetEncrAlgos(Settings):
    Algos = []
    for Name in ("<EncryptionAlgorithmMain>k__BackingField", "<EncryptionAlgorithmKey1>k__BackingField", "<EncryptionAlgorithmKey2>k__BackingField"):
        Algo = DotNetGetByName(Settings, Name, Settings)
        Algos.append(Algo.Obj.Values[0])
    return EncrAlgos(*Algos)

def Decrypt(PathATD, PathK1, PathK2, PathK3, PinCode, Password):
    Settings = GetSettings(PathK3)
    PinCode = DecodePin(PinCode)
    Settings2 = DecryptImage(PathK3, Settings.TK.GetBytes(), Settings.TK, Settings.EncrAlgo3)
    Algos = GetEncrAlgos(Settings2)
    FactorTable = GetDecodeInfo(Settings, PinCode, Password, Settings2)
    return DecryptWithFT(PathATD, PathK1, PathK2, Settings, FactorTable, Algos)

def Finalize(OutDir, Data, ZipPassword):
    print("[+] Zip password is '%s'" % ZipPassword)
    OutZip = os.path.join(OutDir, "decr.zip")
    print("[+] Writing decrypted zip in '%s'..." % OutZip)
    with open(OutZip,"wb") as F:
        for B in Data:
            F.write(bytes((B,)))
    del Data
    print("[+] Done! Extracing zip...")
    OutZip = open(OutZip,"rb")
    Z=zipfile.ZipFile(OutZip)
    for I in Z.infolist():
        F = I.filename
        print("[+] Zip contains: '%s'" % I.filename)
        assert(F.find("..") == -1)
        assert(F[0] != "/")
        assert(F[0] != "\\")
    Z.extractall(path=OutDir, pwd=ZipPassword.encode("ascii"))
    print("[+] Extracted with success!")

def GetFiles(PathATD):
    Path, _ = os.path.splitext(PathATD)
    return ("%s.%s" % (Path, Ext) for Ext in ("atd", "atk1","atk2","atk3"))
