package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.Crypto;
import io.github.angelsl.java.libkdbx.TestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

import static io.github.angelsl.java.libkdbx.TestUtil.unb64;

public class KDBXOuterTest {
    @Test
    public void loadTest() throws Throwable {
        for (String file : TestUtil.TEST_FILES) {
            byte[] data = TestUtil.getResource(file);
            KDBXOuter result = KDBXOuter.parse(data, TestUtil.AAAAA);
            Assertions.assertEquals(result.getXML(), new String(unb64(TestUtil.getResource(file + ".xml.base64")), "UTF-8"));
        }
    }
}
