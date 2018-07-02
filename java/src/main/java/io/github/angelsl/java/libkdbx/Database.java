package io.github.angelsl.java.libkdbx;

import io.github.angelsl.java.libkdbx.format.KDBXBinary;

public class Database {
    private String _name;
    private Group _root;
    private KDBXBinary[] _binaries;

    public Database(String name, Group root, KDBXBinary[] binaries) {
        _name = name;
        _root = root;
        _binaries = binaries;
    }

    public String name() {
        return _name;
    }

    public Group root() {
        return _root;
    }

    public KDBXBinary binary(int i) {
        return _binaries[i];
    }
}
