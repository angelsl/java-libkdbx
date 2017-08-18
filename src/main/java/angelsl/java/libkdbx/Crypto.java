package angelsl.java.libkdbx;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class Crypto {
    public static final int HASH_SHA256 = 0;
    public static final int HASH_SHA512 = 1;

    private static final ThreadLocal<SHA256Digest> _sha256 = ThreadLocal.withInitial(SHA256Digest::new);
    private static final ThreadLocal<SHA512Digest> _sha512 = ThreadLocal.withInitial(SHA512Digest::new);
    private static final ThreadLocal<PaddedBufferedBlockCipher> _aes
            = ThreadLocal.withInitial(() -> new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding()));
    private static final ThreadLocal<ChaCha7539Engine> _chacha = ThreadLocal.withInitial(ChaCha7539Engine::new);

    public Crypto() {}

    public byte[] hash(int type, byte[] src, int index, int count) {
        Digest d;
        switch (type) {
            case HASH_SHA256:
                d = _sha256.get();
                break;
            case HASH_SHA512:
                d = _sha512.get();
                break;
            default:
                return null;
        }

        byte[] ret = new byte[d.getDigestSize()];
        d.reset();
        d.update(src, index, count);
        d.doFinal(ret, 0);
        return ret;
    }

    public byte[] aes256Decrypt(byte[] key, byte[] iv, byte[] src, int index, int count) {
        PaddedBufferedBlockCipher e = _aes.get();
        e.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] buf = new byte[e.getOutputSize(count)];
        int len = e.processBytes(src, index, count, buf, 0);
        try {
            len += e.doFinal(buf, len);
        } catch (InvalidCipherTextException t) {
            return null;
        }

        byte[] ret = new byte[len];
        System.arraycopy(buf, 0, ret, 0, len);
        return ret;
    }

    public byte[] chacha20Decrypt(byte[] key, byte[] iv, byte[] src, int index, int count) {
        ChaCha7539Engine e = _chacha.get();
        e.init(false, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] out = new byte[count];
        e.processBytes(src, index, count, out, 0);
        return out;
    }
}
