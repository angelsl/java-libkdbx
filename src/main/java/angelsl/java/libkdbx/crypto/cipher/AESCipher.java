package angelsl.java.libkdbx.crypto.cipher;

import angelsl.java.libkdbx.crypto.Crypto;

public class AESCipher implements Cipher {
    @Override
    public int getKeyLength() {
        return 32;
    }

    @Override
    public int getIvLength() {
        return 16;
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] iv, byte[] src, int index, int count) {
        return Crypto.getEngine().aes256Decrypt(key, iv, src, index, count);
    }
}
