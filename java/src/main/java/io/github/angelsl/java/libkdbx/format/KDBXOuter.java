package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.KDBXException;
import io.github.angelsl.java.libkdbx.KDBXIRS;

import java.io.UnsupportedEncodingException;

public class KDBXOuter {
    private KDBXIRS _irs;
    private KDBXBinary[] _binaries;
    private String _xml;

    public KDBXIRS getIRS() {
        return _irs;
    }

    public KDBXBinary[] getBinaries() {
        return _binaries;
    }

    public String getXML() {
        return _xml;
    }

    static {
        System.loadLibrary("kdbxouter");
        initNative();
    }

    public static KDBXOuter parse(byte[] in, byte[] key32) throws KDBXException {
        if (key32 == null) {
            throw new NullPointerException("Parameter key32 is null");
        }
        if (key32.length != 32) {
            throw new IllegalArgumentException("Key length must be 32");
        }
        if (in == null) {
            throw new NullPointerException("Parameter in is null");
        }

        NativeResult n = parseNative(in, key32);
        KDBXOuter r = new KDBXOuter();
        try {
            r._xml = new String(n.xml, "UTF-8");
            r._irs = new KDBXIRS(n.irsKey, n.irs);
            r._binaries = new KDBXBinary[n.binaries.length];

            for (int i = 0; i < n.binaries.length; ++i) {
                r._binaries[i] = new KDBXBinary(n.binaries[i], n.binariesProtection[i], r._irs);
            }
        } catch (UnsupportedEncodingException e) {
            throw new KDBXException("Could not decode XML", e);
        } finally {
            for (int i = 0; i < n.xml.length; ++i) {
                n.xml[i] = 0;
            }
        }

        return r;
    }

    private static native NativeResult parseNative(byte[] in, byte[] key32) throws KDBXException;
    private static native void initNative();

    private static class NativeResult {
        byte[] xml;
        int irs;
        byte[] irsKey;
        byte[][] binaries;
        boolean[] binariesProtection;
    }
}
