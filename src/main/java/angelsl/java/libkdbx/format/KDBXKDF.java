package angelsl.java.libkdbx.format;

import angelsl.java.libkdbx.Util;
import angelsl.java.libkdbx.crypto.kdf.AESKDF;
import angelsl.java.libkdbx.crypto.kdf.Argon2KDF;
import angelsl.java.libkdbx.crypto.kdf.KDF;

import java.nio.ByteBuffer;
import java.util.UUID;

class KDBXKDF {
    private KDBXKDF() {}

    public static KDF readKDF(ByteBuffer buf) {
        int kdfStart = buf.position();
        UUIDHandler uuidHandler = new UUIDHandler();
        KDBX.readMap(buf, uuidHandler);
        UUID kdfUuid = uuidHandler.getUUID();
        buf.position(kdfStart);

        if (KDBX.KDF_ARGON2.equals(kdfUuid)) {
            return readArgon2(buf);
        } else if (KDBX.KDF_AES.equals(kdfUuid)) {
            return readAES(buf);
        }

        return null;
    }

    private static KDF readArgon2(ByteBuffer buf) {
        KDF kdf = new Argon2KDF();
        // TODO
        KDBX.readMap(buf, new KDBX.MapHandler() {
            @Override
            public void handleBool(String name, boolean val) {}

            @Override
            public void handleInt(String name, int val) {}

            @Override
            public void handleLong(String name, long val) {
                switch (name) {
                    case "P": // parallelism
                        break;
                    case "M": // memory
                        break;
                    case "I": // iterations
                        break;
                    case "V": // version
                        break;
                }
            }

            @Override
            public void handleString(String name, String val) {}

            @Override
            public void handleByteArray(String name, byte[] val) {
                switch (name) {
                    case "S": // salt
                        break;
                    case "K": // key
                        break;
                    case "A": // associated data
                        break;
                }
            }
        });
        return kdf;
    }

    private static KDF readAES(ByteBuffer buf) {
        final AESKDF kdf = new AESKDF();
        KDBX.readMap(buf, new KDBX.MapHandler() {
            @Override
            public void handleBool(String name, boolean val) {}

            @Override
            public void handleInt(String name, int val) {}

            @Override
            public void handleLong(String name, long val) {
                if ("R".equals(name)) {
                    kdf.setRounds(val);
                }
            }

            @Override
            public void handleString(String name, String val) {}

            @Override
            public void handleByteArray(String name, byte[] val) {
                if ("S".equals(name)) {
                    kdf.setKey(val);
                }
            }
        });
        return kdf;
    }

    private static class UUIDHandler implements KDBX.MapHandler {
        private UUID _uuid = null;

        public UUID getUUID() {
            return _uuid;
        }

        @Override
        public void handleBool(String name, boolean val) {}

        @Override
        public void handleInt(String name, int val) {}

        @Override
        public void handleLong(String name, long val) {}

        @Override
        public void handleString(String name, String val) {}

        @Override
        public void handleByteArray(String name, byte[] val) {
            if (name.equals("$UUID")) {
                _uuid = Util.bytesToUuid(val);
            }
        }
    }
}
