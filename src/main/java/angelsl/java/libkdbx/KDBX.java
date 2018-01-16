package angelsl.java.libkdbx;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class KDBX {
    private static final long SIG_1 = 0x9AA2D903L;
    private static final long SIG_2 = 0xB54BFB67L;
    private static final long VER_MAJOR_MASK = 0xFFFF0000L;
    private static final long VER_MINOR_MASK = 0xFFFFL;

    private static final byte HDR_END = 0;
    private static final byte HDR_COMMENT = 1;
    private static final byte HDR_CIPHER_ID = 2;
    private static final byte HDR_COMPRESSION_FLAGS = 3;
    private static final byte HDR_MASTER_SEED = 4;
    private static final byte HDR_TRANSFORM_SEED = 5;
    private static final byte HDR_TRANSFORM_ROUNDS = 6;
    private static final byte HDR_ENCRYPTION_IV = 7;
    private static final byte HDR_IRS_KEY = 8;
    private static final byte HDR_STREAM_START_BYTES = 9;
    private static final byte HDR_IRS_ID = 10;
    private static final byte HDR_KDF_PARAMETERS = 11;
    private static final byte HDR_PUBLIC_CUSTOM_DATA = 12;

    public static void read() throws KDBXException {
        throw new KDBXException("Not implemented");
    }

    public static String readOuter(byte[] outer) throws KDBXException {
        return readOuter(ByteBuffer.wrap(outer));
    }

    public static String readOuter(final ByteBuffer buf) throws KDBXException {
        buf.order(ByteOrder.LITTLE_ENDIAN);
        try {
            final long sig1 = buf.getInt() & Util.U32_MASK;
            final long sig2 = buf.getInt() & Util.U32_MASK;
            if (sig1 != SIG_1 || sig2 != SIG_2) {
                throw new KDBXException("Invalid magic");
            }

            final long version = buf.getInt() & Util.U32_MASK;
            final long majorVer = (version & VER_MAJOR_MASK) >> 16;
            if (majorVer > 4) {
                throw new KDBXException("File version too new");
            }
            if (majorVer < 2) {
                throw new KDBXException("File version too old");
            }

            if (majorVer == 4) {
                return readOuterKdbx4(buf);
            } else {
                return readOuterKdbx3(buf);
            }
        } catch (BufferUnderflowException bue) {
            throw new KDBXException("Unexpected end-of-file", bue);
        }
    }

    private static String readOuterKdbx3(ByteBuffer buf) throws KDBXException {
        Header hdr = new Header();

        while (true) {
            byte field = buf.get();
            int len = buf.getShort() & Util.U16_MASK;

            byte[] data = new byte[len];
            buf.get(data);

            if (hdr.handleField(field, data)) {
                break;
            }
        }

        // TODO
    }

    private static String readOuterKdbx4(ByteBuffer buf) throws KDBXException {
        Header hdr = new Header();

        while (true) {
            byte field = buf.get();
            int len = buf.getInt(); // This is actually u32, but Java(TM) doesn't support large arrays
            if (len < 0) {
                throw new KDBXException("Header data too large for Java array");
            }

            byte[] data = new byte[len];
            buf.get(data);

            if (hdr.handleField(field, data)) {
                break;
            }
        }

        // TODO
    }

    private static class Header {
        Header() {}

        boolean handleField(byte field, byte[] data) {
            switch (field) {
                case HDR_END:
                    return true;
                case HDR_CIPHER_ID:
                    break;
                case HDR_COMPRESSION_FLAGS:
                    break;
                case HDR_MASTER_SEED:
                    break;
                case HDR_TRANSFORM_SEED:
                    break;
                case HDR_TRANSFORM_ROUNDS:
                    break;
                case HDR_ENCRYPTION_IV:
                    break;
                case HDR_IRS_KEY:
                    break;
                case HDR_STREAM_START_BYTES:
                    break;
                case HDR_IRS_ID:
                    break;
                case HDR_KDF_PARAMETERS:
                    break;
                case HDR_PUBLIC_CUSTOM_DATA:
                    break;
                case HDR_COMMENT:
                    break;
                default:
                    assert false;
                    break;
            }

            return false;
        }
    }
}
