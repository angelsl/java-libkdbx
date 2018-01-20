package angelsl.java.libkdbx.crypto.cipher;

import angelsl.java.libkdbx.crypto.Crypto;

public class ChaCha20Cipher implements Cipher {
    @Override
    public int getKeyLength() {
        return 32;
    }

    @Override
    public int getIvLength() {
        return 12;
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] iv, byte[] src, int index, int count) {
        return Crypto.getEngine().chacha20Decrypt(key, iv, src, index, count);
    }
}
