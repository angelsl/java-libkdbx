package io.github.angelsl.java.libkdbx.format;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class Util {
    private Util() {}

    public static byte[] gunzip(byte[] gz) throws IOException {
        byte[] buf = new byte[gz.length*2];
        try (ByteArrayInputStream bais = new ByteArrayInputStream(gz)) {
            try (GZIPInputStream gzis = new GZIPInputStream(bais)) {
                try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    int rd;
                    while ((rd = gzis.read(buf)) > 0) {
                        baos.write(buf, 0, rd);
                    }
                    return baos.toByteArray();
                }
            }
        }
    }
}
