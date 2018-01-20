package angelsl.java.libkdbx.crypto;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.format.KDBXException;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Crypto {
    private static Crypto _crypto = null;

    static {
        _crypto = new Crypto();
    }

    public static void setEngine(Crypto crypto) {
        if (crypto == null) {
            throw new NullPointerException("Null Crypto object");
        }

        _crypto = crypto;
    }

    public static Crypto getEngine() {
        if (_crypto == null) {
            _crypto = new Crypto();
        }

        return _crypto;
    }

    public static final int HASH_SHA256 = 0;
    public static final int HASH_SHA512 = 1;
    public static final int HASH_BLAKE2B = 2;

    private static final ThreadLocal<SHA256Digest> _sha256 = ThreadLocal.withInitial(SHA256Digest::new);
    private static final ThreadLocal<SHA512Digest> _sha512 = ThreadLocal.withInitial(SHA512Digest::new);
    private static final ThreadLocal<Blake2bDigest> _blake2b = ThreadLocal.withInitial(Blake2bDigest::new);
    private static final ThreadLocal<HMac> _hmacsha256 = ThreadLocal.withInitial(() -> new HMac(new SHA256Digest()));
    private static final ThreadLocal<AESEngine> _aes = ThreadLocal.withInitial(AESEngine::new);
    private static final ThreadLocal<PaddedBufferedBlockCipher> _aesCbc
            = ThreadLocal.withInitial(() -> new PaddedBufferedBlockCipher(new CBCBlockCipher(_aes.get()), new PKCS7Padding()));
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
            case HASH_BLAKE2B:
                d = _blake2b.get();
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
        PaddedBufferedBlockCipher e = _aesCbc.get();
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

    public byte[] aesKdfHalf(byte[] key, byte[] block, int off, long rounds) {
        AESEngine aes = _aes.get();
        aes.init(true, new KeyParameter(key));

        if (rounds < 0) {
            boolean odd = (rounds & 1) == 1;
            rounds >>>= 1;
            for (long i = 0; i < rounds; ++i) {
                aes.processBlock(block, off, block, off);
                aes.processBlock(block, off, block, off);
            }

            if (odd) {
                aes.processBlock(block, off, block, off);
            }
        } else {
            for (long i = 0; i < rounds; ++i) {
                aes.processBlock(block, off, block, off);
            }
        }

        return block;
    }

    /**
     * Decode a KeePass hashed block stream.
     * @param src The byte array containing the stream
     * @param offset The offset in the byte array at which the stream begins
     * @return The decoded data, or <code>null</code> if the stream is invalid
     */
    public byte[] decodeHashedBlockStream(byte[] src, int offset) {
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
        ByteBuffer ms = ByteBuffer.wrap(src);
        ms.position(offset);
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
     * @return The decoded data
     */
    public byte[] decodeHmacBlockStream(byte[] key, byte[] src, int offset) {
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
        ByteBuffer ms = ByteBuffer.wrap(src);
        ms.position(offset);
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

    public byte[] argon2d(final int rounds,
                          final int memoryKb,
                          final int lanes,
                          final int outputLength,
                          final byte[] password,
                          final byte[] salt,
                          final byte[] secret,
                          final byte[] ad,
                          final int version) {
        Blake2bDigest b2b = _blake2b.get();
        int segment_length = memoryKb/(4*lanes);
        int blocks = segment_length*(4*lanes);
        int lane_length = segment_length*4;
        byte[] buf = new byte[blocks * 1024];

        {
            byte[] h0 = new byte[72];

            // compute H0
            {
                int h0buflen = 40 + password.length + salt.length;
                if (secret != null) {
                    h0buflen += secret.length;
                }
                if (ad != null) {
                    h0buflen += ad.length;
                }

                ByteBuffer h0buf = ByteBuffer.allocate(h0buflen);
                h0buf.order(ByteOrder.LITTLE_ENDIAN);
                h0buf.putInt(lanes);
                h0buf.putInt(outputLength);
                h0buf.putInt(memoryKb);
                h0buf.putInt(rounds);
                h0buf.putInt(version);
                h0buf.putInt(0);
                h0buf.putInt(password.length);
                h0buf.put(password);
                h0buf.putInt(salt.length);
                h0buf.put(salt);
                if (secret != null) {
                    h0buf.putInt(secret.length);
                    h0buf.put(secret);
                } else {
                    h0buf.putInt(0);
                }
                if (ad != null) {
                    h0buf.putInt(ad.length);
                    h0buf.put(ad);
                } else {
                    h0buf.putInt(0);
                }
                byte[] h0arr = h0buf.array();
                b2b.reset();
                b2b.update(h0arr, 0, h0buflen);
                b2b.doFinal(h0, 0);
                Util.zeroArray(h0arr);
            }

            // fill the first two blocks in each lane
            for (int i = 0; i < lanes; ++i) {
                Util.intToBytes(0, h0, 64);
                Util.intToBytes(i, h0, 68);
                blake2bLong(h0, 0, 72, buf, i * lane_length, 1024);
                Util.intToBytes(1, h0, 64);
                blake2bLong(h0, 0, 72, buf, i * lane_length + 1024, 1024);
            }
            Util.zeroArray(h0);
        }

        byte[] tmp = new byte[1024];
        for (int pass = 0; pass < rounds; ++pass) {
            for (int slice = 0; slice < 4; ++slice) {
                for (int lane = 0; lane < lanes; ++lane) {
                    int blockIndex = lane*lane_length + slice*segment_length + (pass == 0 && slice == 0 ? 2 : 0);
                    int prevIndex = blockIndex + (blockIndex % lane_length == 0 ? lane_length : 0) - 1;
                    for (int i = 0; i < segment_length; ++i, ++blockIndex, ++prevIndex) {
                        if (blockIndex % lane_length == 1) {
                            prevIndex = blockIndex - 1;
                        }

                        long prand = Util.bytesToLong(buf, prevIndex*1024);
                        long ref_lane = pass == 0 && slice == 0 ? 0 : (prand >>> 32) % lanes;
                        int ref_size =
                                (pass == 0) ?
                                        (slice == 0) ?
                                                (i - 1) :
                                                ((ref_lane == lane) ?
                                                        (((slice * segment_length) + i) - 1) :
                                                        ((slice * segment_length) + ((i == 0) ? -1 : 0))) :
                                        (ref_lane == lane) ?
                                                (((lane_length - segment_length) + i) - 1) :
                                                ((lane_length - segment_length) + ((i == 0) ? -1 : 0));
                        prand &= 0xFFFFFFFFL;
                        int refIndex = (int) (memoryKb + lane_length*ref_lane +
                                                        (int) ((
                                                                (((pass != 0) ?
                                                                        ((slice == (4 - 1)) ? 0 : ((slice + 1) * segment_length)) :
                                                                        0) + ref_size)
                                                                        - 1 - ((ref_size * ((prand * prand) >>> 32)) >>> 32)) % lane_length));
                        boolean xor = version == 0x10 || pass == 0;
                    }
                }
            }
        }

        throw new KDBXException("Not implemented");
    }

    public byte[] blake2bLong(byte[] in, int inOffset, int inLength, byte[] out, int outOffset, int outLength) {
        if (out == null) {
            out = new byte[outLength + outOffset];
        }

        byte[] outLenBytes = Util.intToBytes(outLength);
        if (outLength <= 64) {
            Blake2bDigest b2b = outLength == 64 ? _blake2b.get() : new Blake2bDigest(null, outLength, null, null);
            b2b.update(outLenBytes, 0, 4);
            b2b.update(in, inOffset, inLength);
            b2b.doFinal(out, outOffset);
        } else {
            int remaining;
            byte[] outBuf = new byte[64];
            byte[] inBuf = new byte[64];
            Blake2bDigest b2b = _blake2b.get();
            b2b.reset();
            b2b.update(outLenBytes, 0, 4);
            b2b.update(in, inOffset, inLength);
            b2b.doFinal(outBuf, 0);
            System.arraycopy(outBuf, 0, out, outOffset, 32);
            outOffset += 32;
            remaining = outLength - 32;

            while (remaining > 64) {
                System.arraycopy(outBuf, 0, inBuf, 0, 64);
                b2b.reset();
                b2b.update(inBuf, 0, 64);
                b2b.doFinal(outBuf, 0);
                System.arraycopy(outBuf, 0, out, outOffset, 32);
                outOffset += 32;
                remaining -= 32;
            }

            System.arraycopy(outBuf, 0, inBuf, 0, 64);
            b2b = new Blake2bDigest(null, remaining, null, null);
            b2b.update(inBuf, 0, 64);
            b2b.doFinal(out, outOffset);
        }

        return out;
    }

    private static long rotr64(long x, int rot) {
        return x >>> rot | (x << (64 - rot));
    }
}
