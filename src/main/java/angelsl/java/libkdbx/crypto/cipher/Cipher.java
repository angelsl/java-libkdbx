package angelsl.java.libkdbx.crypto.cipher;

public interface Cipher {
    int getKeyLength();
    int getIvLength();
    byte[] decrypt(byte[] key, byte[] iv, byte[] src, int index, int count);
}
