package io.github.angelsl.java.libkdbx.format;

public class KDBXBinary {
    private boolean _protected;
    private byte[] _data;
    private KDBXIRS _irs;

    public KDBXBinary(byte[] data, boolean prot, KDBXIRS irs) {
        if (data == null) {
            throw new NullPointerException("Parameter data is null");
        }
        if (prot && irs == null) {
            throw new NullPointerException("IRS is required for a protected binary");
        }
        _data = data;
        _protected = prot;
        _irs = prot ? irs : null;
    }

    public byte[] get() {
        byte[] ret = new byte[_data.length];
        System.arraycopy(_data, 0, ret, 0, _data.length);
        if (_protected) {
            _irs.apply(ret);
        }
        return ret;
    }
}
