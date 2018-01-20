package angelsl.java.libkdbx;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.crypto.Crypto;

public class KeePassKey {
    private KeePassKey() {}

    public static byte[] passwordKey(byte[] passwordBytes) {
        return Crypto.getEngine().hash(Crypto.HASH_SHA256, passwordBytes, 0, passwordBytes.length);
    }

    public static byte[] combine(byte[]... rawKeys) {
        byte[] joined = Util.concatenateArrays(rawKeys);
        byte[] combined = Crypto.getEngine().hash(Crypto.HASH_SHA256, joined, 0, joined.length);
        Util.zeroArray(joined);
        return combined;
    }

}
