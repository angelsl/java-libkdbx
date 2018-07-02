package io.github.angelsl.java.libkdbx.format;

import io.github.angelsl.java.libkdbx.Database;
import io.github.angelsl.java.libkdbx.Entry;
import io.github.angelsl.java.libkdbx.Group;
import io.github.angelsl.java.libkdbx.KDBXException;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Base64;

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
        if (binaries == null) {
            binaries = new KDBXBinary[0];
        }
        try (StringReader input = new StringReader(xml)) {
            if (_xppF == null) {
                throw _xppEx;
            }

            XmlPullParser xpp = _xppF.newPullParser();
            xpp.setInput(input);

            while (true) {
                if (xpp.next() == XmlPullParser.START_TAG && "KeePassFile".equals(xpp.getName())) {
                    break;
                }
            }

            String name = "";
            Group root = null;
            while (true) {
                int next = xpp.nextTag();
                if (next == XmlPullParser.START_TAG) {
                    switch (xpp.getName()) {
                        case "Meta":
                            MetaParseResult mpr = parseMeta(xpp, timeFormat, irs, binaries);
                            binaries = mpr.binaries;
                            name = mpr.name;
                            break;
                        case "Root":
                            while (true) {
                                int next2 = xpp.nextTag();
                                if (next2 == XmlPullParser.START_TAG) {
                                    switch (xpp.getName()) {
                                        case "Group":
                                            root = parseGroup(xpp, timeFormat, irs);
                                            break;
                                        default:
                                            skipElement(xpp);
                                            break;
                                    }
                                } else if (next2 == XmlPullParser.END_TAG && "Root".equals(xpp.getName())) {
                                    break;
                                }
                            }
                            break;
                        default:
                            skipElement(xpp);
                            break;
                    }
                } else if (next == XmlPullParser.END_TAG && "KeePassFile".equals(xpp.getName())) {
                    break;
                }
            }

            return new Database(name, root, binaries);
        } catch (Exception e) {
            throw new KDBXException("Failed to parse XML", e);
        }
    }

    private static MetaParseResult parseMeta(XmlPullParser xpp, int timeFormat, KDBXIRS irs, KDBXBinary[] binaries) throws Exception {
        MetaParseResult mpr = new MetaParseResult();
        mpr.name = "";
        while (true) {
            int next = xpp.nextTag();
            if (next == XmlPullParser.START_TAG) {
                switch (xpp.getName()) {
                    case "DatabaseName":
                        mpr.name = xpp.nextText();
                        break;
                    case "Binaries":
                        binaries = parseMetaBinaries(xpp, irs, binaries);
                        break;
                    default:
                        skipElement(xpp);
                        break;
                }
            } else if (next == XmlPullParser.END_TAG && "Meta".equals(xpp.getName())) {
                break;
            }
        }
        mpr.binaries = binaries;
        return mpr;
    }

    private static KDBXBinary[] parseMetaBinaries(XmlPullParser xpp, KDBXIRS irs, KDBXBinary[] binaries) throws Exception {
        while (true) {
            int next = xpp.nextTag();
            if (next == XmlPullParser.START_TAG) {
                switch (xpp.getName()) {
                    case "Binary":
                        int id = -1;
                        for (int i = 0; i < xpp.getAttributeCount(); ++i) {
                            switch (xpp.getAttributeName(i)) {
                                case "ID":
                                    id = Integer.parseInt(xpp.getAttributeValue(i));
                                    break;
                            }
                        }
                        if (id < 0 || (binaries.length > id && binaries[id] != null)) {
                            xpp.nextText();
                            break;
                        }

                        if (id >= binaries.length) {
                            KDBXBinary[] newBinaries = new KDBXBinary[id + 1];
                            System.arraycopy(binaries, 0, newBinaries, 0, binaries.length);
                            binaries = newBinaries;
                        }

                        binaries[id] = parseBinary(xpp, irs);
                        break;
                    default:
                        skipElement(xpp);
                        break;
                }
            } else if (next == XmlPullParser.END_TAG && "Binaries".equals(xpp.getName())) {
                break;
            }
        }
        return binaries;
    }

    private static KDBXBinary parseBinary(XmlPullParser xpp, KDBXIRS irs) throws Exception {
        boolean prot = false, comp = false;
        for (int i = 0; i < xpp.getAttributeCount(); ++i) {
            switch (xpp.getAttributeName(i)) {
                case "Protected":
                    prot = "True".equals(xpp.getAttributeValue(i));
                    break;
                case "Compressed":
                    comp = "True".equals(xpp.getAttributeValue(i));
                    break;
            }
        }
        String b64data = xpp.nextText();
        byte[] data = (comp || prot) ? Base64.getDecoder().decode(b64data) : b64data.getBytes("UTF-8");
        if (comp) {
            // assert !prot;
            data = Util.gunzip(data);
        }
        return new KDBXBinary(data, prot, irs);
    }

    private static Group parseGroup(XmlPullParser xpp, int timeFormat, KDBXIRS irs) throws Exception {
        ArrayList<Group> subgroups = new ArrayList<>();
        ArrayList<Entry> entries = new ArrayList<>();
        String name = "";
        while (true) {
            int next = xpp.nextTag();
            if (next == XmlPullParser.START_TAG) {
                switch (xpp.getName()) {
                    case "Name":
                        name = xpp.nextText();
                        break;
                    case "Entry":
                        entries.add(parseEntry(xpp, timeFormat, irs));
                        break;
                    case "Group":
                        subgroups.add(parseGroup(xpp, timeFormat, irs));
                        break;
                    default:
                        skipElement(xpp);
                        break;
                }
            } else if (next == XmlPullParser.END_TAG && "Group".equals(xpp.getName())) {
                break;
            }
        }

        return new Group(name, subgroups.toArray(new Group[0]), entries.toArray(new Entry[0]));
    }

    private static Entry parseEntry(XmlPullParser xpp, int timeFormat, KDBXIRS irs) throws Exception {
        String name = "";
        String username = "";
        KDBXBinary password = null;

        while (true) {
            int next = xpp.nextTag();
            if (next == XmlPullParser.START_TAG) {
                switch (xpp.getName()) {
                    case "String":
                        String key = null;
                        KDBXBinary value = null;
                        while (true) {
                            int next2 = xpp.nextTag();
                            if (next2 == XmlPullParser.START_TAG) {
                                switch (xpp.getName()) {
                                    case "Key":
                                        key = xpp.nextText();
                                        break;
                                    case "Value":
                                        value = parseBinary(xpp, irs);
                                        break;
                                    default:
                                        skipElement(xpp);
                                        break;
                                }
                            } else if (next2 == XmlPullParser.END_TAG && "String".equals(xpp.getName())) {
                                break;
                            }
                        }

                        switch (key) {
                            case "Title":
                                name = new String(value.get(), "UTF-8");
                                break;
                            case "UserName":
                                username = new String(value.get(), "UTF-8");
                                break;
                            case "Password":
                                password = value;
                                break;
                        }
                        break;
                    default:
                        skipElement(xpp);
                        break;
                }
            } else if (next == XmlPullParser.END_TAG && "Entry".equals(xpp.getName())) {
                break;
            }
        }

        return new Entry(name, username, password);
    }

    private static void skipElement(XmlPullParser xpp) throws Exception {
        while (true) {
            int next = xpp.next();
            switch (next) {
                case XmlPullParser.START_TAG:
                    skipElement(xpp);
                    break;
                case XmlPullParser.END_TAG:
                    return;
            }
        }
    }

    private static class MetaParseResult {
        public String name;
        public KDBXBinary[] binaries;
    }
}
