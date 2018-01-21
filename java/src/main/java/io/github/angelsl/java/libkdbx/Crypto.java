package io.github.angelsl.java.libkdbx;

public class Crypto {
    static {
        System.loadLibrary("kdbxouter");
    }

    private Crypto() {}

    /**
     * Derive a 32-byte master key from the normal KeePass password
     * and/or keyfile
     *
     * @param password Password
     * @param keyfile Keyfile
     * @return The derived key
     * @throws IllegalArgumentException if neither password nor keyfile are provided
     */
    public static byte[] deriveKeePassKey(byte[] password, byte[] keyfile) {
        if (password == null && keyfile == null) {
            throw new IllegalArgumentException("At least one of password or keyfile must be provided");
        } else if (password != null && keyfile == null) {
            return sha256Native(sha256Native(password));
        } else if (password == null /* && keyfile != null */) {
            return sha256Native(keyfile);
        } else /* if (password != null && keyfile != null) */ {
            return sha256Native(sha256Native(password), keyfile);
        }
    }

    /**
     * Calculate the SHA256 hash of multiple byte arrays concatenated in order
     *
     * @param arrays The arrays to hash
     * @return The hash
     * @throws IllegalArgumentException if no arrays are provided
     */
    public static byte[] sha256(byte[]... arrays) {
        if (arrays == null || arrays.length < 1) {
            throw new IllegalArgumentException("At least one array must be provided");
        }
        return sha256Native(arrays);
    }

    public static native byte[] sha256Native(byte[]... passwords);
}
