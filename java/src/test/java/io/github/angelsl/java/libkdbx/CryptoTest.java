package io.github.angelsl.java.libkdbx;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CryptoTest {
    private static Base64.Decoder _b64d = Base64.getDecoder();
    @Test
    public void passwordTest() throws Throwable {
        assertArrayEquals(Crypto.deriveKeePassKey("aaaaa".getBytes("UTF-8"), null),
                _b64d.decode("vCimDDOm83xb2mBLqgg6eK/Btw64uhnXeThcYHyFPsY="));
    }
}
