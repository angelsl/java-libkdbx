package angelsl.java.libkdbx.crypto;

import angelsl.java.libkdbx.Util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class SecureByteArray implements AutoCloseable {
    private static Random _random;

    static {
        try {
            _random = SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException nsae) {
            // something is better than nothing
            _random = new Random();
        }
    }

    private static byte[] xorPad(int arrayLen) {
        byte[] pad = new byte[Math.min(32, arrayLen)];
        _random.nextBytes(pad);
        return pad;
    }

    private byte[] _xor = null;
    private byte[] _array = null;

    /**
     * Construct a new secure byte array wrapper.
     *
     * @param array The array to wrap. The wrapper will encrypt the array in-place.
     */
    public SecureByteArray(byte[] array) {
        this(array, xorPad(array.length));
    }

    /**
     * Construct a new secure byte array wrapper with a specified XOR pad.
     *
     * @param array The array to wrap. The wrapper will encrypt the array in-place.
     * @param pad The XOR pad to use, which may be <code>null</code>, in which case no encryption is done.
     */
    public SecureByteArray(byte[] array, byte[] pad) {
        _array = array;
        _xor = pad;

        if (_xor != null) {
            for (int i = 0; i < array.length; ++i) {
                _array[i] ^= _xor[i % _xor.length];
            }
        }
    }

    /**
     * @return A decrypted copy of the array wrapped by this wrapper.
     */
    public byte[] get() {
        byte[] ret = new byte[_array.length];
        if (_xor != null) {
            for (int i = 0; i < ret.length; ++i) {
                ret[i] = (byte) (_array[i] ^ _xor[i % _xor.length]);
            }
        } else {
            System.arraycopy(_array, 0, ret, 0, _array.length);
        }
        return ret;
    }

    /**
     * @return The length of the protected array.
     */
    public int length() {
        return _array.length;
    }

    /**
     * Destroy the array and XOR pad.
     */
    @Override
    public void close() {
        byte[] array = _array;
        if (array != null) {
            Util.zeroArray(array);
        }

        byte[] xor = _xor;
        if (xor != null) {
            Util.zeroArray(xor);
        }

        _array = _xor = null;
    }

    @Override
    protected void finalize() {
        // should have been zeroed out by now!
        assert _array == null && _xor == null;
        close();
    }
}
