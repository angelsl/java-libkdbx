package io.github.angelsl.java.libkdbx;

import java.util.Arrays;
import java.util.Collections;

public class Group {
    private String _name;
    private Group[] _subgroups;
    private Entry[] _entries;

    public Group(String name, Group[] subgroups, Entry[] entries) {
        _name = name;
        _subgroups = subgroups;
        _entries = entries;

        if (_subgroups == null) {
            _subgroups = new Group[0];
        }

        if (_entries == null) {
            _entries = new Entry[0];
        }
    }

    public String name() {
        return _name;
    }

    public Group[] subgroups() {
        return Arrays.copyOf(_subgroups, _subgroups.length);
    }

    public Entry[] entries() {
        return Arrays.copyOf(_entries, _entries.length);
    }
}
