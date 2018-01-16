package angelsl.java.libkdbx;

class Util {
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
}
