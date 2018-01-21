package io.github.angelsl.java.libkdbx;

public class KDBXIRS {
    static {
        System.loadLibrary("kdbxouter");
    }

    public static final int IRS_NULL = 0;
    public static final int IRS_ARCFOURVARIANT = 1;
    public static final int IRS_SALSA20 = 2;
    public static final int IRS_CHACHA20 = 3;

    private byte[] _key;
    private int _type;

    public KDBXIRS(byte[] key, int type) {
        if (key == null) {
            throw new NullPointerException("Parameter key is null");
        }

        if (type != 2 && type != 3) {
            throw new IllegalArgumentException("Unsupported or invalid IRS type");
        }

        _key = key;
        _type = type;
    }

    /**
     * XOR the stream into a byte array
     *
     * @param text The bytes to XOR with the stream
     * @throws NullPointerException if <code>text</code> is <code>null</code>
     */
    public void apply(byte[] text) {
        if (text == null) {
            throw new NullPointerException("Parameter text is null");
        }

        applyNative(text);
    }

    private native void applyNative(byte[] text);
}
