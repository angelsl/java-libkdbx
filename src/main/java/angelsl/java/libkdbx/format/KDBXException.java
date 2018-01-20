package angelsl.java.libkdbx.format;

public class KDBXException extends RuntimeException {
    public KDBXException(String message) {
        super(message);
    }

    public KDBXException(String message, Throwable cause) {
        super(message, cause);
    }
}
