package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.Database;
import io.github.angelsl.java.libkdbx.KDBXException;
import io.github.angelsl.java.libkdbx.KDBXIRS;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.StringReader;

public class KDBXFile {
    static XmlPullParserFactory _xppF = null;
    static XmlPullParserException _xppEx = null;

    public static final int TIMEFORMAT_UNKNOWN = 0;
    public static final int TIMEFORMAT_ISO8601 = 1;
    public static final int TIMEFORMAT_BASE64 = 2;

    static {
        try {
            _xppF = XmlPullParserFactory.newInstance();
        } catch (XmlPullParserException e) {
            _xppEx = e;
        }
    }

    public static Database parse(byte[] in, byte[] key) throws KDBXException {
        return parse(KDBXOuter.parse(in, key));
    }

    public static Database parse(KDBXOuter outer) throws KDBXException {
        return parse(outer.getXML(),
                outer.getVersionMajor() == 4 ? TIMEFORMAT_BASE64 : TIMEFORMAT_ISO8601,
                outer.getIRS(),
                outer.getBinaries());
    }

    public static Database parse(String xml, int timeFormat, KDBXIRS irs, KDBXBinary[] binaries) throws KDBXException {
        try (StringReader input = new StringReader(xml)) {
            if (_xppF == null) {
                throw _xppEx;
            }

            Database ret = new Database();

            XmlPullParser xpp = _xppF.newPullParser();
            xpp.setInput(input);

            while (true) {
                if (xpp.next() == XmlPullParser.START_TAG && xpp.getName().equals("KeePassFile")) {
                    break;
                }
            }
            while (true) {
                int next = xpp.nextTag();
                if (next == XmlPullParser.START_TAG) {
                    switch (xpp.getName()) {
                        case "Meta":
                            binaries = parseMeta(xpp, timeFormat, ret, irs, binaries);
                            break;
                        case "Root":
                            parseRoot(xpp, timeFormat, ret, irs, binaries);
                            break;
                    }
                } else if (next == XmlPullParser.END_TAG && xpp.getName().equals("KeePassFile")) {
                    break;
                }
            }

            return ret;
        } catch (Exception e) {
            throw new KDBXException("Failed to parse XML", e);
        }
    }

    private static KDBXBinary[] parseMeta(XmlPullParser xpp, int timeFormat, Database ret, KDBXIRS irs, KDBXBinary[] binaries) {
        return null;
    }

    private static void parseRoot(XmlPullParser xpp, int timeFormat, Database ret, KDBXIRS irs, KDBXBinary[] binaries) {
    }
}
