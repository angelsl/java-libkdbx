package angelsl.java.libkdbx.format;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.crypto.Crypto;
import angelsl.java.libkdbx.KeePassKey;
import angelsl.java.libkdbx.crypto.cipher.Cipher;
import angelsl.java.libkdbx.crypto.kdf.KDF;

import java.io.UnsupportedEncodingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class KDBXFile {
    /**
     * Read a KDBX file.
     *
     * The master key is typically derived from a password and/or keyfile.
     * Use {@link KeePassKey#passwordKey(byte[])} and {@link KeePassKey#combine(byte[]...)} to
     * derive a key compatible with typical KeePass keys.
     *
     * @param file The contents of the KDBX file
     * @param key The master key; destroyed after use
     * @throws KDBXException if an error occurs while reading
     */
    public static void read(byte[] file, byte[] key) throws KDBXException {
        throw new KDBXException("Not implemented");
    }

    public static String readOuter(byte[] outer, byte[] key) throws KDBXException {
        return readOuter(ByteBuffer.wrap(outer), key);
    }

    public static String readOuter(final ByteBuffer buf, byte[] key) throws KDBXException {
        buf.order(ByteOrder.LITTLE_ENDIAN);
        try {
            final long sig1 = buf.getInt() & Util.U32_MASK;
            final long sig2 = buf.getInt() & Util.U32_MASK;
            if (sig1 != KDBX.SIG_1 || sig2 != KDBX.SIG_2) {
                throw new KDBXException("Invalid magic");
            }

            final long version = buf.getInt() & Util.U32_MASK;
            final long majorVer = (version & KDBX.VER_MAJOR_MASK) >> 16;
            if (majorVer > 4) {
                throw new KDBXException("File version too new");
            }
            if (majorVer < 2) {
                throw new KDBXException("File version too old");
            }

            if (majorVer == 4) {
                return readOuterKdbx4(buf, key);
            } else {
                return readOuterKdbx3(buf, key);
            }
        } catch (BufferUnderflowException bue) {
            throw new KDBXException("Unexpected end-of-file", bue);
        }
    }

    private static String readOuterKdbx3(ByteBuffer buf, byte[] key) {
        KDBXHeader hdr = KDBXHeader.fromKdbx3(buf);
        KDF kdf = hdr.getKDF();
        Cipher cipher = hdr.getCipher();
        if (hdr.getStreamStartBytes() == null) {
            throw new KDBXException("Invalid file (stream start bytes missing)");
        }

        kdf.transform(key);
        byte[] composed = KDBX.composeKey(hdr.getMasterSeed(), key);
        Util.zeroArray(key);
        byte[] cryptoKey = KDBX.deriveCryptoKey(composed, cipher.getKeyLength());
        Util.zeroArray(composed);

        byte[] cipherText = new byte[buf.limit() - buf.position()];
        buf.get(cipherText);
        byte[] plainText = cipher.decrypt(cryptoKey, hdr.getIV(), cipherText, 0, cipherText.length);
        Util.zeroArray(cryptoKey);
        if (plainText == null) {
            throw new KDBXException("Wrong key (decryption failed)");
        }

        byte[] ssb = new byte[32];
        System.arraycopy(plainText, 0, ssb, 0, 32);
        if (!Arrays.equals(ssb, hdr.getStreamStartBytes())) {
            Util.zeroArray(plainText);
            Util.zeroArray(ssb); // does this reveal anything?
            throw new KDBXException("Wrong key (stream start bytes differ)");
        }

        byte[] xml;
        byte[] compressed = Crypto.getEngine().decodeHashedBlockStream(plainText, 32);
        Util.zeroArray(plainText);
        if (compressed == null) {
            throw new KDBXException("Corrupted file (hashed block stream decoding failed)");
        }

        if (hdr.getCompressionAlgorithmID() == KDBX.COMPRESSION_GZIP) {
            xml = Util.gunzip(compressed);
            if (xml == null) {
                throw new KDBXException("Corrupted file (GZIP decompression failed)");
            }
            Util.zeroArray(compressed);
        } else {
            xml = compressed;
        }

        try {
            return new String(xml, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            assert false;
            throw new KDBXException("UTF-8 not supported by runtime");
        } finally {
            Util.zeroArray(xml);
        }
    }

    private static String readOuterKdbx4(ByteBuffer buf, byte[] key) {
        KDBXHeader hdr = KDBXHeader.fromKdbx4(buf);
        KDF kdf = hdr.getKDF();
        Cipher cipher = hdr.getCipher();

        kdf.transform(key);
        byte[] composed = KDBX.composeKey(hdr.getMasterSeed(), key);
        Util.zeroArray(key);
        byte[] cryptoKey = KDBX.deriveCryptoKey(composed, cipher.getKeyLength());
        byte[] hmacKey = KDBX.deriveHmacKey(composed);
        Util.zeroArray(composed);

        throw new KDBXException("Not implemented");
    }

    private KDBXFile() {}
}
