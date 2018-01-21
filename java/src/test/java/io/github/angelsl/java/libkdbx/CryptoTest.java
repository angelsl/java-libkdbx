package io.github.angelsl.java.libkdbx;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static io.github.angelsl.java.libkdbx.TestUtil.unb64;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CryptoTest {
    @Test
    public void passwordTest() throws Throwable {
        assertArrayEquals(Crypto.deriveKeePassKey("aaaaa".getBytes("UTF-8"), null),
                unb64("vCimDDOm83xb2mBLqgg6eK/Btw64uhnXeThcYHyFPsY="));
    }
}
