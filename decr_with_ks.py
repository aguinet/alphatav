import os
from PIL import Image
from decrypt import GetSettings, DecryptWithFT, Finalize, DecryptImage, TimeKey, GetEncrAlgos, GetFiles
from Crypto.Cipher import AES

def CrackWithFT(PathATD, PathK1, PathK2, PathK3, PathFT):
    Settings = GetSettings(PathK3)
    print("[+] Get settings from '%s'..." % PathK3)
    Settings2 = DecryptImage(PathK3, Settings.TK.GetBytes(), Settings.TK, Settings.EncrAlgo3)
    Algos = GetEncrAlgos(Settings2)
    FT = open(PathFT, "rb").read()
    return DecryptWithFT(PathATD, PathK1, PathK2, Settings, FT, Algos)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: %s atd_file recovered_ks" % sys.argv[0])
        sys.exit(1)
    PathATD, PathK1, PathK2, PathK3 = GetFiles(sys.argv[1])
    Data,ZipPassword = CrackWithFT(PathATD, PathK1, PathK2, PathK3, sys.argv[2])
    Finalize(os.path.dirname(PathATD), Data, ZipPassword)
