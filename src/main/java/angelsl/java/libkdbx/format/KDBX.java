package angelsl.java.libkdbx.format;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.crypto.Crypto;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.UUID;

class KDBX {
    static final long SIG_1 = 0x9AA2D903L;
    static final long SIG_2 = 0xB54BFB67L;
    static final long VER_MAJOR_MASK = 0xFFFF0000L;
    static final long VER_MINOR_MASK = 0xFFFFL;

    static final byte HDR_END = 0;
    static final byte HDR_COMMENT = 1;
    static final byte HDR_CIPHER_ID = 2;
    static final byte HDR_COMPRESSION_FLAGS = 3;
    static final byte HDR_MASTER_SEED = 4;
    static final byte HDR_TRANSFORM_SEED = 5;
    static final byte HDR_TRANSFORM_ROUNDS = 6;
    static final byte HDR_ENCRYPTION_IV = 7;
    static final byte HDR_IRS_KEY = 8;
    static final byte HDR_STREAM_START_BYTES = 9;
    static final byte HDR_IRS_ID = 10;
    static final byte HDR_KDF_PARAMETERS = 11;
    static final byte HDR_PUBLIC_CUSTOM_DATA = 12;

    static final int COMPRESSION_NONE = 0;
    static final int COMPRESSION_GZIP = 1;

    static final int IRS_NULL = 0;
    static final int IRS_ARCFOURVARIANT = 1;
    static final int IRS_SALSA20 = 2;
    static final int IRS_CHACHA20 = 3;

    static final UUID CIPHER_CHACHA20 = UUID.fromString("2b8a03d6-6f8b-b54c-a524-339a31dbb59a");
    static final UUID CIPHER_AES = UUID.fromString("e6f2c131-71bf-5043-be58-05216afc5aff");

    static final UUID KDF_AES = UUID.fromString("9af3d9c9-8a62-6044-bf74-0d08c18a4fea");
    static final UUID KDF_ARGON2 = UUID.fromString("df6d63ef-298c-4b44-91f7-a9a403e30a0c");

    static final byte MAP_NONE = 0;
    // static final byte MAP_BYTE = 0x02;
    // static final byte MAP_UINT16 = 0x03;
    static final byte MAP_UINT32 = 0x04;
    static final byte MAP_UINT64 = 0x05;
    static final byte MAP_BOOL = 0x08;
    // static final byte MAP_SBYTE = 0x0A;
    // static final byte MAP_INT16 = 0x0B;
    static final byte MAP_INT32 = 0x0C;
    static final byte MAP_INT64 = 0x0D;
    // static final byte MAP_FLOAT = 0x10;
    // static final byte MAP_DOUBLE = 0x11;
    // static final byte MAP_DECIMAL = 0x12;
    // static final byte MAP_CHAR = 0x17;
    static final byte MAP_STRING = 0x18;
    static final byte MAP_BYTEARRAY = 0x42;

    static void readMap(ByteBuffer buf, MapHandler into) throws KDBXException {
        buf.get();
        int majorVer = buf.get() & 0xFF;
        if (majorVer > 1) {
            throw new KDBXException("KDBX map structure too new");
        }

        while (true) {
            int type = buf.get() & 0xFF;
            int nameLen = buf.getInt();
            byte[] nameBytes = new byte[nameLen];
            buf.get(nameBytes);
            int valLen = buf.getInt();
            int newPos = buf.position() + valLen;

            String name;
            try {
                 name = new String(nameBytes, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new KDBXException("Invalid UTF-8 string in KDBX map structure", e);
            }

            switch (type) {
                case MAP_NONE:
                    break;
                case MAP_INT32: {
                    assert valLen == 4;
                    int val = buf.getInt();
                    into.handleInt(name, val);
                    break;
                }
                case MAP_UINT32: {
                    assert valLen == 4;
                    long val = buf.getInt() & Util.U32_MASK;
                    into.handleLong(name, val);
                    break;
                }
                case MAP_INT64:
                case MAP_UINT64: {
                    // yes, Java's long is signed
                    // *shrug*
                    assert valLen == 8;
                    long val = buf.getLong();
                    into.handleLong(name, val);
                    break;
                }
                case MAP_BOOL: {
                    assert valLen == 1;
                    boolean val = buf.get() != 0;
                    into.handleBool(name, val);
                    break;
                }
                case MAP_STRING: {
                    byte[] valBytes = new byte[valLen];
                    buf.get(valBytes);
                    String val;
                    try {
                        val = new String(valBytes, "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        throw new KDBXException("Invalid UTF-8 string in KDBX map structure", e);
                    }
                    into.handleString(name, val);
                    break;
                }
                case MAP_BYTEARRAY: {
                    byte[] val = new byte[valLen];
                    buf.get(val);
                    into.handleByteArray(name, val);
                    break;
                }
                default:
                    assert false;
                    break;
            }

            assert buf.position() == newPos;
            buf.position(newPos);

            if (type == MAP_NONE) {
                break;
            }
        }
    }

    static byte[] composeKey(byte[] seed, byte[] combined) {
        // seed comes from plaintext header, not secret
        // combined comes from password, secret
        byte[] ret = new byte[65];
        System.arraycopy(seed, 0, ret, 0, 32);
        System.arraycopy(combined, 0, ret, 32, 32);
        ret[64] = 1;
        // intention is to pass directly to derive{Crypto,Hmac}Key and then zero out
        return ret;
    }

    static byte[] deriveCryptoKey(byte[] composed, int length) {
        if (length > 32) {
            // both the ciphers we support use a key length of 32 bytes
            // we'll implement this when we need it
            throw new UnsupportedOperationException("Maximum supported cipher key length is 32 bytes");
        }
        if (composed.length < 64) {
            throw new IllegalArgumentException("Composed key too short");
        }

        byte[] ret = new byte[length];
        byte[] hashed = Crypto.getEngine().hash(Crypto.HASH_SHA256, composed, 0, 64);
        System.arraycopy(hashed, 0, ret, 0, length);
        Util.zeroArray(hashed);
        return ret;
    }

    static byte[] deriveHmacKey(byte[] composed) {
        if (composed.length < 65) {
            throw new IllegalArgumentException("Composed key too short");
        }
        return Crypto.getEngine().hash(Crypto.HASH_SHA512, composed, 0, 65);
    }

    interface MapHandler {
        void handleBool(String name, boolean val);
        void handleInt(String name, int val); // <32-bit are promoted to int
        void handleLong(String name, long val);
        void handleString(String name, String val);
        void handleByteArray(String name, byte[] val);
        // void handleFloat(String name, float val);
        // void handleDouble(String name, double val);
    }

    private KDBX() {}
}
