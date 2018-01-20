package angelsl.java.libkdbx;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

public class TestUtil {
    private TestUtil() {}

    public static byte[] getResource(String path) {
        InputStream is = TestUtil.class.getClassLoader().getResourceAsStream(path);
        if (is == null) {
            return null;
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[0x4000];
        int len;
        try {
            while ((len = is.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }
        } catch (IOException e) {
            return null;
        } finally {
            try {
                is.close();
            } catch (IOException ignored) {}
        }
        return baos.toByteArray();
    }

    public static byte[] stringToKey(String s) {
        try {
            byte[] in = s.getBytes("UTF-8");
            return KeePassKey.combine(KeePassKey.passwordKey(in));
        } catch (UnsupportedEncodingException e) {
            assert false;
            throw new RuntimeException("Runtime does not support UTF-8", e);
        }
    }
}
