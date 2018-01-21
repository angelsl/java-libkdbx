package io.github.angelsl.java.libkdbx;

public class KDBXException extends Exception {
    public KDBXException(String message) {
        super(message);
    }

    public KDBXException(String message, Throwable cause) {
        super(message, cause);
    }
}
