package angelsl.java.libkdbx;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Crypto {
    public static final int HASH_SHA256 = 0;
    public static final int HASH_SHA512 = 1;

    private static final ThreadLocal<SHA256Digest> _sha256 = ThreadLocal.withInitial(SHA256Digest::new);
    private static final ThreadLocal<SHA512Digest> _sha512 = ThreadLocal.withInitial(SHA512Digest::new);
    private static final ThreadLocal<HMac> _hmacsha256 = ThreadLocal.withInitial(() -> new HMac(new SHA256Digest()));
    private static final ThreadLocal<PaddedBufferedBlockCipher> _aes
            = ThreadLocal.withInitial(() -> new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding()));
    private static final ThreadLocal<ChaCha7539Engine> _chacha = ThreadLocal.withInitial(ChaCha7539Engine::new);

    public Crypto() {}

    /**
     * Calculate a hash
     * @param type The type of hash (<code>HASH_SHA256</code> or <code>HASH_SHA512</code>)
     * @param src The byte array containing data for which the hash is to be calculated
     * @param index The offset in the byte array at which the data begins
     * @param count The length of the data
     * @return The hash
     */
    public byte[] hash(int type, byte[] src, int index, int count) {
        Digest d;
        switch (type) {
            case HASH_SHA256:
                d = _sha256.get();
                break;
            case HASH_SHA512:
                d = _sha512.get();
                break;
            default:
                return null;
        }

        byte[] ret = new byte[d.getDigestSize()];
        d.reset();
        d.update(src, index, count);
        d.doFinal(ret, 0);
        return ret;
    }

    /**
     * Calculate a HMAC-SHA256 MAC.
     * @param key The raw HMAC key
     * @param src The byte array containing data for which the MAC is to be calculated
     * @param index The offset in the byte array at which the data begins
     * @param count The length of the data
     * @return The 32-byte MAC
     */
    public byte[] hmacsha256(byte[] key, byte[] src, int index, int count) {
        HMac h = _hmacsha256.get();

        byte[] ret = new byte[h.getMacSize()];
        h.init(new KeyParameter(key));
        h.update(src, index, count);
        h.doFinal(ret, 0);
        return ret;
    }

    /**
     * Decode a AES256-encrypted byte array.
     * @param key The AES256 key
     * @param src The encrypted byte array
     * @param index The offset in the byte array at which the encrypted data begins
     * @param count The length of the encrypted data
     * @return The decrypted data
     */
    public byte[] aes256Decrypt(byte[] key, byte[] iv, byte[] src, int index, int count) {
        PaddedBufferedBlockCipher e = _aes.get();
        e.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] buf = new byte[e.getOutputSize(count)];
        int len = e.processBytes(src, index, count, buf, 0);
        try {
            len += e.doFinal(buf, len);
        } catch (InvalidCipherTextException t) {
            return null;
        }

        return Arrays.copyOf(buf, len);
    }

    /**
     * Decode a ChaCha20-encrypted byte array.
     * @param key The ChaCha20 key
     * @param src The encrypted byte array
     * @param index The offset in the byte array at which the encrypted data begins
     * @param count The length of the encrypted data
     * @return The decrypted data
     */
    public byte[] chacha20Decrypt(byte[] key, byte[] iv, byte[] src, int index, int count) {
        ChaCha7539Engine e = _chacha.get();
        e.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] out = new byte[count];
        e.processBytes(src, index, count, out, 0);
        return out;
    }

    /**
     * Decode a KeePass hashed block stream.
     * @param src The byte array containing the stream
     * @param offset The offset in the byte array at which the stream begins
     * @param length The length of the stream
     * @return The decoded data
     */
    public byte[] decodeHashedBlockStream(byte[] src, int offset, int length) {
        /*
        hashedBlock
        [uint index]
        [byte[32] hash = sha256(data)]
        [int len]
        [byte[len] data]

        hashedBlockStream
        [hashedBlock... blocks]
        [hashedBlock {hash = 0, len = 0} lastblock]
        */
        ByteBuffer ms = ByteBuffer.wrap(src, offset, length);
        ByteBuffer os = ByteBuffer.allocate(1024 * 1024);
        ms.order(ByteOrder.LITTLE_ENDIAN);
        os.order(ByteOrder.LITTLE_ENDIAN);
        try {
            long blockCount = 0;
            final byte[] blockHash = new byte[32];
            byte[] blockData = new byte[1024 * 1024];
            for (;;) {
                // Java has no unsigned int, sigh
                final long blockIndex = ((long)ms.getInt()) & 0xFFFFFFFFL;
                if (blockIndex != blockCount) {
                    return null;
                }

                ms.get(blockHash);

                final int blockLen = ms.getInt();
                if (blockLen == 0) {
                    for (byte b : blockHash) {
                        if (b != 0) {
                            return null;
                        }
                    }

                    os.flip();
                    byte[] ret = new byte[os.limit()];
                    os.get(ret);
                    return ret;
                } else if (blockLen > blockData.length) {
                    blockData = new byte[1 << (32-Integer.numberOfLeadingZeros(blockLen))];
                }

                ms.get(blockData, 0, blockLen);

                if (!Arrays.equals(blockHash, hash(HASH_SHA256, blockData, 0, blockLen))) {
                    return null;
                }

                os.put(blockData, 0, blockLen);
                ++blockCount;
            }
        } catch (BufferUnderflowException e) {
            return null;
        }
    }

    /**
     * Decode a KeePass HMAC-ed block stream.
     * @param key The raw key for HMAC
     * @param src The byte array containing the stream
     * @param offset The offset in the byte array at which the stream begins
     * @param length The length of the stream
     * @return The decoded data
     */
    public byte[] decodeHmacBlockStream(byte[] key, byte[] src, int offset, int length) {
        /*
        hmacBlock
        [byte[32] hmac = hmac256(sha512(ulongindex || key), ulongindex || len || data)]
        [int len]
        [byte[len] data]

        hmacBlockStream
        [hmacBlock... blocks]
        [hmacBlock {len = 0} lastblock]
        */
        HMac hmac = _hmacsha256.get();
        ByteBuffer ms = ByteBuffer.wrap(src, offset, length);
        ByteBuffer os = ByteBuffer.allocate(1024 * 1024);
        ms.order(ByteOrder.LITTLE_ENDIAN);
        os.order(ByteOrder.LITTLE_ENDIAN);
        try {
            long blockCount = 0;
            final byte[] theirHmac = new byte[32];
            final byte[] ourHmac = new byte[32];
            byte[] blockData = new byte[1024 * 1024];
            for (;;) {
                ms.get(theirHmac);

                final int blockLen = ms.getInt();
                if (blockLen > blockData.length) {
                    blockData = new byte[1 << (32-Integer.numberOfLeadingZeros(blockLen))];
                }

                ms.get(blockData, 0, blockLen);

                byte[] blockCountBytes = Util.longToBytes(blockCount);
                hmac.init(new KeyParameter(getHmacKey(key, blockCountBytes)));
                hmac.update(blockCountBytes, 0, 8);
                hmac.update(Util.intToBytes(blockLen), 0, 4);
                hmac.update(blockData, 0, blockLen);
                hmac.doFinal(ourHmac, 0);

                if (!Arrays.equals(ourHmac, theirHmac)) {
                    return null;
                }

                if (blockLen == 0) {
                    os.flip();
                    byte[] ret = new byte[os.limit()];
                    os.get(ret);
                    return ret;
                }

                os.put(blockData, 0, blockLen);
                ++blockCount;
            }
        } catch (BufferUnderflowException e) {
            return null;
        }
    }

    /**
     * Get a 64-byte HMAC key from a raw key (typically 64 bytes) and a 64-bit nonce
     * @param key The raw key
     * @param nonce The nonce
     * @return The HMAC key
     */
    public byte[] getHmacKey(byte[] key, long nonce) {
        return getHmacKey(key, Util.longToBytes(nonce));
    }

    /**
     * Get a 64-byte HMAC key from a raw key (typically 64 bytes) and a nonce
     * @param key The raw key
     * @param nonce The nonce
     * @return The HMAC key
     */
    public byte[] getHmacKey(byte[] key, byte[] nonce) {
        Digest d = _sha512.get();
        byte[] ret = new byte[d.getDigestSize()];
        d.reset();
        d.update(nonce, 0, 8);
        d.update(key, 0, key.length);
        d.doFinal(ret, 0);
        return ret;
    }
}
