package angelsl.java.libkdbx.format;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.crypto.cipher.AESCipher;
import angelsl.java.libkdbx.crypto.cipher.ChaCha20Cipher;
import angelsl.java.libkdbx.crypto.cipher.Cipher;
import angelsl.java.libkdbx.crypto.kdf.AESKDF;
import angelsl.java.libkdbx.crypto.kdf.KDF;

import java.nio.ByteBuffer;
import java.util.UUID;

class KDBXHeader {
    private Cipher _cipher = null;
    private KDF _kdf = null;
    private long _compressionAlgorithmId = 0;
    private byte[] _masterSeed = null;
    private byte[] _iv = null;
    private byte[] _irsKey = null;
    private byte[] _streamStartBytes = null;
    private long _irsId = -1;

    private KDBXHeader() {}

    public Cipher getCipher() {
        return _cipher;
    }

    public long getCompressionAlgorithmID() {
        return _compressionAlgorithmId;
    }

    public byte[] getMasterSeed() {
        return _masterSeed;
    }

    public byte[] getIV() {
        return _iv;
    }

    public byte[] getIRSKey() {
        return _irsKey;
    }

    public byte[] getStreamStartBytes() {
        return _streamStartBytes;
    }

    public KDF getKDF() {
        return _kdf;
    }

    public long getIRSID() {
        return _irsId;
    }

    private void validate() {
        if (_kdf == null) {
            throw new KDBXException("Invalid file (KDF missing)");
        }
        if (_cipher == null) {
            throw new KDBXException("Invalid file (cipher missing)");
        }
        if (_masterSeed == null) {
            throw new KDBXException("Invalid file (master seed missing)");
        }
        if (_iv == null) {
            throw new KDBXException("Invalid file (IV missing)");
        }
        if (_irsKey == null) {
            throw new KDBXException("Invalid file (inner random stream key missing)");
        }
        if (_irsId == -1) {
            throw new KDBXException("Invalid file (inner random stream type missing)");
        }
    }

    /**
     * Handle the raw data for a header field.
     *
     * @param field The field ID
     * @param data The data
     * @return <code>true</code> if this field marks the end of the header
     */
    private boolean handleField(int field, int length, ByteBuffer data) {
        switch (field) {
            case KDBX.HDR_CIPHER_ID: {
                UUID cipherId = Util.readUuid(data);
                if (KDBX.CIPHER_AES.equals(cipherId)) {
                    _cipher = new AESCipher();
                } else if (KDBX.CIPHER_CHACHA20.equals(cipherId)) {
                    _cipher = new ChaCha20Cipher();
                } else {
                    throw new KDBXException("Unsupported cipher");
                }
                break;
            }
            case KDBX.HDR_COMPRESSION_FLAGS:
                _compressionAlgorithmId = data.getInt() & Util.U32_MASK;
                break;
            case KDBX.HDR_MASTER_SEED:
                _masterSeed = new byte[length];
                data.get(_masterSeed);
                break;
            case KDBX.HDR_TRANSFORM_SEED: {
                byte[] seed = new byte[length];
                data.get(seed);
                if (_kdf == null) {
                    _kdf = new AESKDF(seed, 0);
                } else if (_kdf instanceof AESKDF) {
                    AESKDF kdf = (AESKDF) _kdf;
                    kdf.setKey(seed);
                } else {
                    assert false;
                }
                break;
            }
            case KDBX.HDR_TRANSFORM_ROUNDS: {
                long rounds = data.getLong();
                if (_kdf == null) {
                    _kdf = new AESKDF(null, rounds);
                } else if (_kdf instanceof AESKDF) {
                    AESKDF kdf = (AESKDF) _kdf;
                    kdf.setRounds(rounds);
                } else {
                    assert false;
                }
                break;
            }
            case KDBX.HDR_ENCRYPTION_IV:
                _iv = new byte[length];
                data.get(_iv);
                break;
            case KDBX.HDR_IRS_KEY:
                _irsKey = new byte[length];
                data.get(_irsKey);
                break;
            case KDBX.HDR_STREAM_START_BYTES:
                _streamStartBytes = new byte[length];
                data.get(_streamStartBytes);
                break;
            case KDBX.HDR_IRS_ID:
                _irsId = data.getInt() & Util.U32_MASK;
                break;
            case KDBX.HDR_KDF_PARAMETERS:
                assert _kdf == null;
                _kdf = KDBXKDF.readKDF(data);
                break;
            case KDBX.HDR_END:
                data.position(data.position() + length);
                return true;
            case KDBX.HDR_PUBLIC_CUSTOM_DATA:
                // skip, we don't implement plugins
            case KDBX.HDR_COMMENT:
                data.position(data.position() + length);
                break;
            default:
                assert false;
                break;
        }

        return false;
    }

    /**
     * Parses a KDBX 3 header from a byte buffer.
     *
     * @param buf The byte buffer, which must be positioned at the start of the header
     * @return The parsed header
     */
    public static KDBXHeader fromKdbx3(ByteBuffer buf) throws KDBXException {
        KDBXHeader hdr = new KDBXHeader();

        while (true) {
            int field = buf.get() & 0xFF;
            int len = buf.getShort() & Util.U16_MASK;
            int newPos = buf.position() + len;

            boolean end = hdr.handleField(field, len, buf);

            assert buf.position() == newPos;
            buf.position(newPos);

            if (end) {
                break;
            }
        }

        hdr.validate();
        return hdr;
    }

    /**
     * Parses a KDBX 4 header from a byte buffer.
     *
     * @param buf The byte buffer, which must be positioned at the start of the header
     * @return The parsed header
     */
    public static KDBXHeader fromKdbx4(ByteBuffer buf) throws KDBXException {
        KDBXHeader hdr = new KDBXHeader();

        while (true) {
            int field = buf.get() & 0xFF;
            int len = buf.getInt(); // This is actually u32, but Java(TM) doesn't support large arrays
            if (len < 0) {
                throw new KDBXException("Header data too large for Java array");
            }
            int newPos = buf.position() + len;

            boolean end = hdr.handleField(field, len, buf);

            assert buf.position() == newPos;
            buf.position(newPos);

            if (end) {
                break;
            }
        }

        hdr.validate();
        return hdr;
    }
}
