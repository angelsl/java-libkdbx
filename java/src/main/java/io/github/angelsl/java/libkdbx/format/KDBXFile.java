package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.Database;
import io.github.angelsl.java.libkdbx.KDBXException;

public class KDBXFile {
    public static Database parse(byte[] in, byte[] key) throws KDBXException {
        return parse(KDBXOuter.parse(in, key));
    }

    public static Database parse(KDBXOuter outer) throws KDBXException {
        throw new RuntimeException("Not implemented");
    }
}
