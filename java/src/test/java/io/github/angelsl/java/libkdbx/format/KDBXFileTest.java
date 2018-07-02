package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.Crypto;
import io.github.angelsl.java.libkdbx.Database;
import io.github.angelsl.java.libkdbx.TestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

import static io.github.angelsl.java.libkdbx.TestUtil.unb64;

public class KDBXFileTest {
    @Test
    public void loadTest() throws Throwable {
        for (String file : TestUtil.TEST_FILES) {
            byte[] data = TestUtil.getResource(file);
            Database result = KDBXFile.parse(data, TestUtil.AAAAA);
        }
    }
}
