package angelsl.java.libkdbx.crypto.kdf;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.crypto.Crypto;

public class AESKDF implements KDF {
    private byte[] _key = null;
    private long _rounds = 0;

    public AESKDF() {}

    public AESKDF(byte[] key, long rounds) {
        _key = key;
        _rounds = rounds;
    }

    public void setRounds(long rounds) {
        this._rounds = rounds;
    }

    public void setKey(byte[] key) {
        this._key = key;
    }

    @Override
    public void transform(byte[] input) {
        if (_rounds == 0) {
            throw new IllegalArgumentException("AES-KDF rounds is zero (parameters unset?)");
        }
        if (_key == null) {
            throw new IllegalArgumentException("AES-KDF key is null (parameters unset?)");
        }
        if (_key.length != 32) {
            throw new IllegalArgumentException("Invalid AES-KDF AES-256 key length");
        }
        if (input.length != 32) {
            throw new IllegalArgumentException("Invalid AES-KDF input length");
        }

        Thread t = new Thread(() -> Crypto.getEngine().aesKdfHalf(_key, input, 0, _rounds));
        t.run();
        Crypto.getEngine().aesKdfHalf(_key, input, 16, _rounds);
        try {
            t.join();
        } catch (InterruptedException ie) {
            throw new RuntimeException("AES-KDF interrupted");
        }
        byte[] hashed = Crypto.getEngine().hash(Crypto.HASH_SHA256, input, 0, 32);
        System.arraycopy(hashed, 0, input, 0, 32);
        Util.zeroArray(hashed);
    }
}
