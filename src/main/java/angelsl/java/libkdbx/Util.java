package angelsl.java.libkdbx;

import angelsl.java.libkdbx.crypto.SecureByteArray;
import angelsl.java.libkdbx.format.KDBXException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

public class Util {
    public static final int U16_MASK = 0xFFFF;
    public static final long U32_MASK = 0xFFFFFFFFL;

    private Util() {}

    /**
     * Convert a 32-bit integer to its constituent bytes in little-endian.
     * @param i The integer
     * @return The 4 bytes
     */
    public static byte[] intToBytes(int i) {
        return new byte[] {
                (byte) (i & 0xFF),
                (byte) ((i >> 8) & 0xFF),
                (byte) ((i >> 16) & 0xFF),
                (byte) ((i >> 24) & 0xFF),
        };
    }

    /**
     * Convert a 32-bit integer to its constituent bytes in little-endian in-place in an array.
     * @param i The integer
     * @param array The array to place the bytes into
     * @param pos The array index to place the bytes at
     */
    public static void intToBytes(int i, byte[] array, int pos) {
        array[pos] = (byte) (i & 0xFF);
        array[pos+1] = (byte) ((i >> 8) & 0xFF);
        array[pos+2] = (byte) ((i >> 16) & 0xFF);
        array[pos+3] = (byte) ((i >> 24) & 0xFF);
    }

    public static int bytesToInt(byte[] array, int index) {
        return ((int) array[index]) |
                (((int) array[index + 1]) << 8) |
                (((int) array[index + 2]) << 16) |
                (((int) array[index + 3]) << 24);
    }

    /**
     * Convert a 64-bit integer to its constituent bytes in little-endian.
     * @param i The integer
     * @return The 8 bytes
     */
    public static byte[] longToBytes(long i) {
        return new byte[] {
                (byte) (i & 0xFF),
                (byte) ((i >> 8) & 0xFF),
                (byte) ((i >> 16) & 0xFF),
                (byte) ((i >> 24) & 0xFF),
                (byte) ((i >> 32) & 0xFF),
                (byte) ((i >> 40) & 0xFF),
                (byte) ((i >> 48) & 0xFF),
                (byte) ((i >> 56) & 0xFF),
        };
    }

    /**
     * Convert a 64-bit integer to its constituent bytes in little-endian in-place in an array.
     * @param i The integer
     * @param array The array to place the bytes into
     * @param pos The array index to place the bytes at
     */
    public static void longToBytes(long i, byte[] array, int pos) {
        array[pos] = (byte) (i & 0xFF);
        array[pos+1] = (byte) ((i >> 8) & 0xFF);
        array[pos+2] = (byte) ((i >> 16) & 0xFF);
        array[pos+3] = (byte) ((i >> 24) & 0xFF);
        array[pos+4] = (byte) ((i >> 32) & 0xFF);
        array[pos+5] = (byte) ((i >> 40) & 0xFF);
        array[pos+6] = (byte) ((i >> 48) & 0xFF);
        array[pos+7] = (byte) ((i >> 56) & 0xFF);
    }

    public static long bytesToLong(byte[] array, int index) {
        return ((long) array[index]) |
                (((long) array[index + 1]) << 8) |
                (((long) array[index + 2]) << 16) |
                (((long) array[index + 3]) << 24) |
                (((long) array[index + 4]) << 32) |
                (((long) array[index + 5]) << 40) |
                (((long) array[index + 6]) << 48) |
                (((long) array[index + 7]) << 56);
    }

    /**
     * Parse a UUID from a byte array
     *
     * @param bytes The byte array containing the UUID.
     * @return The parsed UUID
     * @throws KDBXException if <code>bytes</code> is less than 16 bytes long
     */
    public static UUID bytesToUuid(byte[] bytes) throws KDBXException {
        if (bytes.length < 16) {
            throw new KDBXException("Not enough data to construct UUID");
        }
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return readUuid(bb);
    }

    /**
     * Parse a UUID from a byte array
     *
     * @param bytes The byte array containing the UUID.
     * @return The parsed UUID
     * @throws KDBXException if <code>bytes</code> is less than 16 bytes long
     */
    public static UUID readUuid(ByteBuffer buf) {
        buf.order(ByteOrder.LITTLE_ENDIAN);
        long left = ((buf.getInt() & 0xFFFFFFFFL) << 32) |
                (buf.getShort() & 0xFFFFL) << 16 |
                (buf.getShort() & 0xFFFFL);
        buf.order(ByteOrder.BIG_ENDIAN);
        long right = buf.getLong();
        buf.order(ByteOrder.LITTLE_ENDIAN);
        return new UUID(left, right);
    }

    /**
     * Zeroes the given array
     *
     * @param array The array to zero
     */
    public static void zeroArray(byte[] array) {
        for (int i = 0; i < array.length; ++i) {
            array[i] = 0;
        }
    }

    public static byte[] concatenateArrays(byte[]... arrays) {
        int sum = 0;
        for (byte[] array : arrays) {
            sum += array.length;
        }

        byte[] joined = new byte[sum];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, joined, pos, array.length);
            pos += array.length;
        }

        return joined;
    }

    public static byte[] concatenateArrays(SecureByteArray... arrays) {
        int sum = 0;
        for (SecureByteArray array : arrays) {
            sum += array.length();
        }

        byte[] joined = new byte[sum];
        int pos = 0;
        for (SecureByteArray array : arrays) {
            byte[] plain = array.get();
            System.arraycopy(plain, 0, joined, pos, array.length());
            Util.zeroArray(plain);
            pos += array.length();
        }

        return joined;
    }

    public static byte[] cloneArray(byte[] array) {
        byte[] ret = new byte[array.length];
        System.arraycopy(array, 0, ret, 0, ret.length);
        return ret;
    }

    public static byte[] gunzip(byte[] compressed) {
        // ByteArrayOutputStream.close() is no-op
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // ByteArrayInputStream.close() is no-op
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            byte[] buf = new byte[0x4000];
            int len;
            while ((len = gis.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }
}
