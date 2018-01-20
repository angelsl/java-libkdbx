package angelsl.java.libkdbx.format;

import angelsl.java.libkdbx.TestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class KDBXFileTest {
    @Test
    public void kdbx3Test() {
        byte[] in = TestUtil.getResource("kdbx3.kdbx");
        String xml = KDBXFile.readOuter(in, TestUtil.stringToKey("aaaaa"));
        Assertions.assertEquals(xml, KDBX3_KDBX_XML);
    }

    private static final String KDBX3_KDBX_XML = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n" +
            "<KeePassFile>\n" +
            "\t<Meta>\n" +
            "\t\t<Generator>KeePass</Generator>\n" +
            "\t\t<HeaderHash>9h4zwPgGcftApxboNOZloPyDmegESOj/gSlgjbi5Pho=</HeaderHash>\n" +
            "\t\t<DatabaseName />\n" +
            "\t\t<DatabaseNameChanged>2018-01-19T15:32:43Z</DatabaseNameChanged>\n" +
            "\t\t<DatabaseDescription />\n" +
            "\t\t<DatabaseDescriptionChanged>2018-01-19T15:32:43Z</DatabaseDescriptionChanged>\n" +
            "\t\t<DefaultUserName />\n" +
            "\t\t<DefaultUserNameChanged>2018-01-19T15:32:43Z</DefaultUserNameChanged>\n" +
            "\t\t<MaintenanceHistoryDays>365</MaintenanceHistoryDays>\n" +
            "\t\t<Color />\n" +
            "\t\t<MasterKeyChanged>2018-01-19T15:32:43Z</MasterKeyChanged>\n" +
            "\t\t<MasterKeyChangeRec>-1</MasterKeyChangeRec>\n" +
            "\t\t<MasterKeyChangeForce>-1</MasterKeyChangeForce>\n" +
            "\t\t<MemoryProtection>\n" +
            "\t\t\t<ProtectTitle>False</ProtectTitle>\n" +
            "\t\t\t<ProtectUserName>False</ProtectUserName>\n" +
            "\t\t\t<ProtectPassword>True</ProtectPassword>\n" +
            "\t\t\t<ProtectURL>False</ProtectURL>\n" +
            "\t\t\t<ProtectNotes>False</ProtectNotes>\n" +
            "\t\t</MemoryProtection>\n" +
            "\t\t<RecycleBinEnabled>False</RecycleBinEnabled>\n" +
            "\t\t<RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>\n" +
            "\t\t<RecycleBinChanged>2018-01-19T15:32:57Z</RecycleBinChanged>\n" +
            "\t\t<EntryTemplatesGroup>AAAAAAAAAAAAAAAAAAAAAA==</EntryTemplatesGroup>\n" +
            "\t\t<EntryTemplatesGroupChanged>2018-01-19T15:32:43Z</EntryTemplatesGroupChanged>\n" +
            "\t\t<HistoryMaxItems>10</HistoryMaxItems>\n" +
            "\t\t<HistoryMaxSize>6291456</HistoryMaxSize>\n" +
            "\t\t<LastSelectedGroup>8c2sqyFat0qUJ6jNmxk4lQ==</LastSelectedGroup>\n" +
            "\t\t<LastTopVisibleGroup>8c2sqyFat0qUJ6jNmxk4lQ==</LastTopVisibleGroup>\n" +
            "\t\t<Binaries />\n" +
            "\t\t<CustomData />\n" +
            "\t</Meta>\n" +
            "\t<Root>\n" +
            "\t\t<Group>\n" +
            "\t\t\t<UUID>8c2sqyFat0qUJ6jNmxk4lQ==</UUID>\n" +
            "\t\t\t<Name>test</Name>\n" +
            "\t\t\t<Notes />\n" +
            "\t\t\t<IconID>49</IconID>\n" +
            "\t\t\t<Times>\n" +
            "\t\t\t\t<CreationTime>2018-01-19T15:32:43Z</CreationTime>\n" +
            "\t\t\t\t<LastModificationTime>2018-01-19T15:32:43Z</LastModificationTime>\n" +
            "\t\t\t\t<LastAccessTime>2018-01-19T15:32:43Z</LastAccessTime>\n" +
            "\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t<LocationChanged>2018-01-19T15:32:43Z</LocationChanged>\n" +
            "\t\t\t</Times>\n" +
            "\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t<LastTopVisibleEntry>ESNGyC2shUyjr4ga2eA/EA==</LastTopVisibleEntry>\n" +
            "\t\t\t<Entry>\n" +
            "\t\t\t\t<UUID>ESNGyC2shUyjr4ga2eA/EA==</UUID>\n" +
            "\t\t\t\t<IconID>0</IconID>\n" +
            "\t\t\t\t<ForegroundColor />\n" +
            "\t\t\t\t<BackgroundColor />\n" +
            "\t\t\t\t<OverrideURL />\n" +
            "\t\t\t\t<Tags />\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>Notes</Key>\n" +
            "\t\t\t\t\t<Value>Notes</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>Password</Key>\n" +
            "\t\t\t\t\t<Value Protected=\"True\">3dqk6NAE5+U=</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>Title</Key>\n" +
            "\t\t\t\t\t<Value>Sample Entry</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>URL</Key>\n" +
            "\t\t\t\t\t<Value>https://keepass.info/</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>UserName</Key>\n" +
            "\t\t\t\t\t<Value>User Name</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<AutoType>\n" +
            "\t\t\t\t\t<Enabled>True</Enabled>\n" +
            "\t\t\t\t\t<DataTransferObfuscation>0</DataTransferObfuscation>\n" +
            "\t\t\t\t\t<Association>\n" +
            "\t\t\t\t\t\t<Window>Target Window</Window>\n" +
            "\t\t\t\t\t\t<KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}</KeystrokeSequence>\n" +
            "\t\t\t\t\t</Association>\n" +
            "\t\t\t\t</AutoType>\n" +
            "\t\t\t\t<History />\n" +
            "\t\t\t</Entry>\n" +
            "\t\t\t<Entry>\n" +
            "\t\t\t\t<UUID>CRWlj0bUTkyok6R4MwPztQ==</UUID>\n" +
            "\t\t\t\t<IconID>0</IconID>\n" +
            "\t\t\t\t<ForegroundColor />\n" +
            "\t\t\t\t<BackgroundColor />\n" +
            "\t\t\t\t<OverrideURL />\n" +
            "\t\t\t\t<Tags />\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>Password</Key>\n" +
            "\t\t\t\t\t<Value Protected=\"True\">daZB+o0=</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>Title</Key>\n" +
            "\t\t\t\t\t<Value>Sample Entry #2</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>URL</Key>\n" +
            "\t\t\t\t\t<Value>https://keepass.info/help/kb/testform.html</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<String>\n" +
            "\t\t\t\t\t<Key>UserName</Key>\n" +
            "\t\t\t\t\t<Value>Michael321</Value>\n" +
            "\t\t\t\t</String>\n" +
            "\t\t\t\t<AutoType>\n" +
            "\t\t\t\t\t<Enabled>True</Enabled>\n" +
            "\t\t\t\t\t<DataTransferObfuscation>0</DataTransferObfuscation>\n" +
            "\t\t\t\t\t<Association>\n" +
            "\t\t\t\t\t\t<Window>*Test Form - KeePass*</Window>\n" +
            "\t\t\t\t\t\t<KeystrokeSequence />\n" +
            "\t\t\t\t\t</Association>\n" +
            "\t\t\t\t</AutoType>\n" +
            "\t\t\t\t<History />\n" +
            "\t\t\t</Entry>\n" +
            "\t\t\t<Group>\n" +
            "\t\t\t\t<UUID>RT+Uo7Uo5U6EhCen5T6FVg==</UUID>\n" +
            "\t\t\t\t<Name>General</Name>\n" +
            "\t\t\t\t<Notes />\n" +
            "\t\t\t\t<IconID>48</IconID>\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n" +
            "\t\t\t</Group>\n" +
            "\t\t\t<Group>\n" +
            "\t\t\t\t<UUID>UicRq2fK/E2n/6UbpFOxHg==</UUID>\n" +
            "\t\t\t\t<Name>Windows</Name>\n" +
            "\t\t\t\t<Notes />\n" +
            "\t\t\t\t<IconID>38</IconID>\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n" +
            "\t\t\t</Group>\n" +
            "\t\t\t<Group>\n" +
            "\t\t\t\t<UUID>VGLLgjAyfEC/7fY0B8WcGw==</UUID>\n" +
            "\t\t\t\t<Name>Network</Name>\n" +
            "\t\t\t\t<Notes />\n" +
            "\t\t\t\t<IconID>3</IconID>\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n" +
            "\t\t\t</Group>\n" +
            "\t\t\t<Group>\n" +
            "\t\t\t\t<UUID>AoMG9oLQfESZBMOxjEssng==</UUID>\n" +
            "\t\t\t\t<Name>Internet</Name>\n" +
            "\t\t\t\t<Notes />\n" +
            "\t\t\t\t<IconID>1</IconID>\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n" +
            "\t\t\t</Group>\n" +
            "\t\t\t<Group>\n" +
            "\t\t\t\t<UUID>ggM9ksV6kkKAFo2+qJm7kg==</UUID>\n" +
            "\t\t\t\t<Name>eMail</Name>\n" +
            "\t\t\t\t<Notes />\n" +
            "\t\t\t\t<IconID>19</IconID>\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n" +
            "\t\t\t</Group>\n" +
            "\t\t\t<Group>\n" +
            "\t\t\t\t<UUID>rDt1mC1lok2Ip69i0LxTOA==</UUID>\n" +
            "\t\t\t\t<Name>Homebanking</Name>\n" +
            "\t\t\t\t<Notes />\n" +
            "\t\t\t\t<IconID>37</IconID>\n" +
            "\t\t\t\t<Times>\n" +
            "\t\t\t\t\t<CreationTime>2018-01-19T15:32:57Z</CreationTime>\n" +
            "\t\t\t\t\t<LastModificationTime>2018-01-19T15:32:57Z</LastModificationTime>\n" +
            "\t\t\t\t\t<LastAccessTime>2018-01-19T15:32:57Z</LastAccessTime>\n" +
            "\t\t\t\t\t<ExpiryTime>2018-01-19T15:32:28Z</ExpiryTime>\n" +
            "\t\t\t\t\t<Expires>False</Expires>\n" +
            "\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
            "\t\t\t\t\t<LocationChanged>2018-01-19T15:32:57Z</LocationChanged>\n" +
            "\t\t\t\t</Times>\n" +
            "\t\t\t\t<IsExpanded>True</IsExpanded>\n" +
            "\t\t\t\t<DefaultAutoTypeSequence />\n" +
            "\t\t\t\t<EnableAutoType>null</EnableAutoType>\n" +
            "\t\t\t\t<EnableSearching>null</EnableSearching>\n" +
            "\t\t\t\t<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n" +
            "\t\t\t</Group>\n" +
            "\t\t</Group>\n" +
            "\t\t<DeletedObjects />\n" +
            "\t</Root>\n" +
            "</KeePassFile>";
}
