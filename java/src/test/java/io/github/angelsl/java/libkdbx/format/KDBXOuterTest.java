package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.Crypto;
import io.github.angelsl.java.libkdbx.TestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

public class KDBXOuterTest {
    private static String[] _testFiles = {
            "kdbx3_aes_gzip_binary.kdbx",
            "kdbx3_aes_gzip.kdbx",
            "kdbx3_aes_none.kdbx",
            "kdbx3_chacha20_gzip.kdbx",
            "kdbx3_chacha20_none.kdbx",
            "kdbx4_aes_aeskdf_gzip.kdbx",
            "kdbx4_aes_aeskdf_none.kdbx",
            "kdbx4_aes_argon2_gzip.kdbx",
            "kdbx4_chacha20_aeskdf_gzip.kdbx",
            "kdbx4_chacha20_aeskdf_none.kdbx",
            "kdbx4_chacha20_argon2_gzip_binary.kdbx",
            "kdbx4_chacha20_argon2_gzip.kdbx"
    };

    private static byte[] _aaaaa;

    static {
        try {
            _aaaaa = Crypto.deriveKeePassKey("aaaaa".getBytes("UTF-8"), null);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void loadTest() throws Throwable {
        for (String file : _testFiles) {
            byte[] data = TestUtil.getResource(file);
            KDBXOuter result = KDBXOuter.parse(data, _aaaaa);
            Assertions.assertEquals(result.getXML(), "");
        }
    }
}
