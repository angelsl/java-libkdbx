package io.github.angelsl.java.libkdbx;

import io.github.angelsl.java.libkdbx.format.KDBXBinary;

public class Entry {
    private String _name;
    private String _username;
    private KDBXBinary _password;

    public Entry(String name, String username, KDBXBinary password) {
        _name = name;
        _username = username;
        _password = password;
    }

    public String name() {
        return _name;
    }

    public String username() {
        return _username;
    }

    public KDBXBinary password() {
        return _password;
    }
}
