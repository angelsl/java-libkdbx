package angelsl.java.libkdbx.crypto;

import angelsl.java.libkdbx.crypto.Crypto;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CryptoTest {
    private static final byte[] _p1 = Base64.getDecoder().decode("EYAt/7shgc79zsYAp1TDJvlvxLqdjqQ7BayKBrLhD2UsVrt+G9miy68VwlJDcABzGGGIcYqSLIPb8voPlnscHL9g1FCZRAsfzfkLiMxS95SsF+1QWJ7bmSk3oijekzQz+KWS4puv2tNWaKSRhqS3ifplYn+Ny8QhhTonYaLiQTnE148mvxX5/Twa+vD5SRKFgBkueDG1pSzhcV1hiHkxcyZqzK8VkMnlbGVCc9HTJzsnoeGJs8gIDzFiRU63l3XD6YbJj31jcO9PSQvLcjJbDUohOeaXqMBeYr19skp7LdTwf4pLCZi+wzHxOWq8PJz/BzgEll6OK0HGayy/5b2k1Bs32/OnEASxY3W0pm5VoSUgfasSd5d2YVNJhZ5r/t50TGVPhWCpV/YzUjLo2oXScckGnmcRkl2EwHqgXotmRmSXQFkJBhzFdya03iRkjobNdhPUZF92YroHysXmCflrzQzOUJoryGqtQSdBXLM4IDLz0ud3kuIEId2fATtX3m4sSBEYlT3soq6pJiI4NAYGz6qS8jcS9Dsqyi+9i8cvVmK5FROhIIr1By85zWu/zO3WmDKQxOw3GlTW7ssOLhbmedC/fh/yZa8gneoH2CbPav5B5vOUnpJ2gvq/yzG/5tgZUlSb/03O5DODcCYCL0EtBoTMzEgjUts+SfskMpl9YLY=");
    private static final byte[] _k1 = Base64.getDecoder().decode("Ee6G0jRqsHMCvxEta3NSuJLErfIakPUAeF22UamxmQU=");
    private static final byte[] _p2 = Base64.getDecoder().decode("qGug1c9um4H4hVnXs1/JUCULHfqDEf038pTWwkqRv8uK4ag+EcQ1odRvSDUB+2W8jvU+NI/XUpduaOI7mNk3Z8aOTNK2iz5h1XwmE8nINvcuGTNUUos7so8R0Kjh+gn6OOBvcq6TBgK33V8TsT7OpTLrDX6m4hQ6UplDpbuWf9tyK9voWMNImxMwnXUrJwFQQip29uyLVFXLNCAUT2BHIF6DoYVj5k1uonJqdUWfDiqY8mKRH4nu59eFHCSjNEuz6XwWqIZ87VzcB1N6IN4PKyX1e139tQDUlLmt3ckpy24mt4zJiWakHAQGtBg2dMf5dfD+rbjutTN7QhPMzhCSszzkU2hSRqK+UF9Y9wHoniDytGfZKh22OAJYTUdT2E70cwDbUSBepy9NP11Ylr0yk6Py2RqpuIkfLhtm+flba3gRY4QADU0Akw04jOrAXaFEJrqjYP4zS7p3uyIE+K018dTkRzI5MoZW8kYMcCyeX9B5ItI/uAt63RjJiFEq+5tfApoW2xZvCvMzTW24J9qO2FxSitba9jnIamkZcKk0K/aqrW6RiIO6ChffC2qewrY+O7D02HHEhAthTnGsVppK/yF2DXlr/FDYl4C+++vOKqiz2jT5P1OF5ihiMDoSDrN9lQxJJ7Q80j5fHEDxBYggkiPJ+XtlUL/N8SdRCcwWxok=");
    private static final byte[] _k2 = Base64.getDecoder().decode("zEFm34UD83cI9ZkjE5TgoEKdFkkVOBhETHs1jevJckk=");

    private final Crypto c = new Crypto();

    @Test
    public void aes256Test() {
        byte[] i1a = Base64.getDecoder().decode("EHDwQbta0hkcWEZkQK3S1Q==");
        byte[] aesOut1 = Base64.getDecoder().decode("48iRpJayfrYNnF/aoJh4Ms2l2V8M/cx38Uqg0bAzQTgCRvzyIU0y+jPv7AjZZS0BlWOi1+4fol09N1wTG8Jy4Pj5i0hpXgDYzPB76u7aeG9Yqv7fhpYTbq01klVKFwbqXwSn1qPF5PWkZ+KHI/291E7p4slNJGmVTyuNym5Sbwsf0FkWdJm0iRZDeMvIQAlGzdG9H8O/CB7Vd3EtxPWWl70pe86jE291p2k9fDxROsdqlNcWpRkmAC6ZcadP1tRGXksIrA0l2whJVyLE3Cmr0IjDya0itVXJ5P7Su3WCgJpAQat1M2Bb3PWElJ6f6n4p1GMzWt6O9yuy7ZXb3/tDZIilL0vnLleuxg0f+OfI9TWun+Nt5o6GZIGuI4t9x9wkXVMceBgiFoU02yAbjDgjKhFeJwdfOzGGs3TZqEZDCKlJ7Hg7iRHlgHMDx1x//dpFzFom99TziiTSWIigpA9YjVQc5KX4sTg3fh7U5LW+mUPKaFvlDIGFB4kI/dh4LkbE6K7tytcKdv3AGghhmqU2CFSEwi7ZaJOQRCWmVyx2aJjwBMdS08y1tU4oIpcTCrFhPAGitL2gG8A1E9Ds9JSK6cvBaUYbau9OT0jrFZhPMyQHYCpcSp8OpXOgrJ1bU2ugq73h9v5U6IVeekjGB0ZWTfwnH3K7wCB4BEtulSW3Uu2QS3k7lOFr19rfrxrcEqw7");
        byte[] i2a = Base64.getDecoder().decode("VbckxCFBDCDVgnNvtpu6XQ==");
        byte[] aesOut2 = Base64.getDecoder().decode("Y/Zz6jE5TM2Q4IRxw/qxAlTOIQgaERYi9eXDEcG1M/VwcBfbjyDd48GCaRda6/jclv/yaUWTJB2RrtZasoty00fzG59rN+Ok/YsZYmhmreZ5hWpHPhJBCOcP512oDb+Iw6N2CxsHQ67dNuT4Q65fc3AZZsPI/5yF1CZvRK095JqwJ+k958c/Ehu2UI8wrMUvB+V1pTnpXZ0T828e/SgcNaDGoqv/O3qwyXIhuJdmDkvtB5F+ik+uSxSM3RGQrhtCPHl+zQgcpDEcY2o/Sv3SGbtH2x4eEDw1m71TwoUqhipwzPYfxAciBeR4ebzNOHe5JSi+qCDaEiCIsnUmw0GKMvwfNaXjKORR7ltsnm36oluX91547ktdYpwIl5TizoPk8TOHmjbsIA+fai0pXuPwFXaLgFeRjXOtwOv+uo3nPFECrtZwLjsNBDqNcZ5wD26ig/ucFh6ROruWj6VN+Go/C9khZc1geW1If5UnrFbaFodAdt4CsWpn9RDCq0Hhwa6ZvZmlp9wrgXtk6H/9awsFRdqdix0CWY6TRoQiC5/SAoKbCA4GXNGfvWW9zZVyXHe85R8ob6k2jzzn3TWS8VH2+nvVxuM1RCALOq9A4k9ydrkMXX8AJfqos7minUb300Q1ZwSs2LjqPzlb0j4AoaRb3v5icjLMdTL+iCgu5XdO5eKrQpIYp8V64jhiYYkAY3F+");
        byte[] p3 = Base64.getDecoder().decode("9Ku+JLdpbdMpJGx10DoaoJLVmvCCdcKv5tKbGPsssqvUQjfmV3bR997ux93JY+oBK6UFLnyM8n/oDz7lzlTY/XLAoY0CM0kcA6MRlK3l5oLomexVJ4QvR0+4/kc47CiJFcprCcJc//hb6CrZel7RAym7/DVogtXukFk9SjQB5BZ6iH7iet3AjJr0+T5ZVszx5vsefPDzIJP0fHhoHrXDWQQTXvLg74hM+nCadIiXlDqNTGM542cmhmfr7f1kWG3lMKA6RvfZEfdy0oF/WawKXeg92tFRiXac7diL9AKL56ICtUPoXE5DsztsxxDmpi264Y8UJn2bk6cpnlgeThz15uvefaNpIQCa+ieW5cJmtUar0RNyd8AlZyKcv771JGUfd+AkBymJUL+PeStVBa3kwugSc30Igm8quRWBzWFBpdbCd27iQa0cIYBT4/2Uz2J0t/zW4rHnFvRw+k4TCINeTdRVk40/AYE69VH9tJ9ylemzDRVka8Il2mB5cUdfCRn89ZUoPzzUNLZ7nO1f6mFU/mRlYPtt+eISMLksxo852+w4AL8KSVat3thf6c/Vxu/+JHPj+agej/yzFg6Cp24mQcABJuqiSrQNuIEiDg8TPGrJLaEcVuFDGnDDVzJHKjdpOacO058FXNq+1UEn+4Hsn9mkuXnNCevfvQt53/OCxY1KuNRnBWnKxNHGXoCfGx/v1rdYonG9nC+8LhY=");
        byte[] i3a = Base64.getDecoder().decode("k4t85zwPtN1CrISacNr0qA==");
        byte[] aesOut3 = Base64.getDecoder().decode("l6QsigdHgoQqpmgJPnWPKcnfl/qBH/E9Ysu4PWjPV9GXLPRuQ3kphT+M7EaB1HqmCOfyEE2+OB+b5Qw2zKtBfZiQc8RrRnJudINqk/bOnuVn9GZOhmPGztA1LLSBCIpsVTAcwWGW/BR9dOHIVuCCRxl8E/4vaYo7J9bk3knEwJ3KOiOQGZIZKXbrRkkPbamBV9TzS9AbKNdclnzjYXY0yj0ZIDdH0DUOsgTplHBfO3woW3a41KdbKKGwBN+IjjjObNnWOYK3w2odRbLEsDDN8H4LWHAmh4HQKZ16hF+i0OOMv6g7jPNJ7gsiQFP5tN+jH/xIQRt5tCEdMMzICLm+t9II0rpI5sVf3bc4y4wImQO7LtYXA694bvhZsT5xN72KEnMNeZUGhzLrr26uh+aXr8zGe+mlIck4G5aBy6jcjwx1zuaAyhJQbtTqGbX6PO+jfqdErNfxcxum9OgDZDG4IqbaZt3YKdWKFO19E4JVK4zMrxdlykmnHdKUKAk+94VXdcdQTNspDXbsR+rVgaYPzKGI+ipRzSJayczHTBi6v9NXlPZFXLwQkzdKwNFaJVVykDhEADppqAFETIQfenfd2Qb28h337HDO8uLhGHc4UZkElR4sHs8OXQzXWxHjFwkpsJPg2yP4rtUp1e0njz8EiUk1sp6RnCVkjzu+HMjrj2p0I7P0sdD5egoUapw/Dv4vmE9nGJo/7d10vID+jOGm1Q==");

        assertArrayEquals(_p1, c.aes256Decrypt(_k1, i1a, aesOut1, 0, aesOut1.length));
        assertArrayEquals(_p2, c.aes256Decrypt(_k2, i2a, aesOut2, 0, aesOut2.length));
        assertArrayEquals(p3, c.aes256Decrypt(_k1, i3a, aesOut3, 0, aesOut3.length));
    }

    @Test
    public void chacha20Test() {
        byte[] i1c = Base64.getDecoder().decode("R7DHLv99dJMoIpIK");
        byte[] chachaOut1 = Base64.getDecoder().decode("DMKu/2fRwPjsg1Ldx2R3oAO8NxuRy1SPSOQxPjm06+ytuAY8Revye0PkkKbuHApqfcF64iPsWYixPKolUiJMUS5chlwO09H1buHh+xccMJkOQEwKWsaHppMmJZtYrIoGKPhM9n/BO+oRQ7W78mL3pkHLDYPR5kCHhX2Hfnovn2SGdH7zKIBeiVMgRNS4v84k3bvLbBTw9B2U5lRE6itdfpIh+81j6WD38+E1MlqHWZ+tb1klQiKOYZZk03tfzIWRnZKcp/t/VLnEU6dFpMJl+tDK/nZZjwsRcKmWUgFnX4xBA69JNRpNkv/Xs2pxeCmwzlTbqMcZUoFsBl/hhx470ygkTeNLWghfqLdMh8hsrW3OfeDx/sAj+DyEdSkgXlptKBLlreFh6WDxoLoBPaUfCJgBrwWUipE1pHmboD0015uHb5iTp8xuHCtk56vKAblaE2kQi+6EeWB+rLqZgNd8mjkGewM9FfKmssRKoIelqV4Ppv603A9goi4L0YmkU5vWRKab7ZQQDtfI56YrZFiW/75D5vuRrv8+yrS5JtMSRA6J5+4V8aCKWx1mVqfK0oUHNfCq4YDyi6TziETd9b0rhIENDEOqUzaAlDXf9WhHNiG4Wt04+XSZ8i1S+wsx49qLUd+v/pWozssXwK+1GhtcIJdmFySOzR7hiEXEdiC0xpI=");
        byte[] i2c = Base64.getDecoder().decode("zWaLPoNQzltvG34A");
        byte[] chachaOut2 = Base64.getDecoder().decode("O6x3ho2zPenslD52OR8zZliK9kJ1DwS1cCEC8jtPSwYTL5SCy2wsAAPunLz6b0zjtijrN2PpKt4kFU3nBYPayD706tD14Qga4LCI5GvlDs1+IQgerd8OaWfs3P9fPAv1YMyPqyU0hHAycknks2ZdG/P0e/xDR8Da+ndlEHBhY6/LCO/tL8/6GclFZ44VkgKl2TvL4g3DWRE+6ms1K22Rc77NBvk8lgu+rkYWU1uz42LuNLa4dEnixWOQiLgk3UM7Pd0kXKUw4dLGXn8b6Y9aI73zc01/Q/7Ze0zQG62EUSL4hznTknxoSl1H0DmuStE1KeVHkt2PjZYV2liMvyzYypdyP2b3wd+yyaxkvcxdRAVncPGbpefqE/bYkUfKx3UwGUYh/xXqHXCw6IQIOlhZTlvFKw18wg34Bykz3kN/4MvTI7FQhWC/xDhyB36WhNx6Xrc78QxBd7e0VKTBhD9OZ5vBtzXPCILyeXFzG+3WBaztoNz/QL9H2Ib8yO7Z7co8cffyVs7K/eq6AUj2BkqiRypYv79HTJN6aCRu1JYulpVLpDica2aDWBOyKqEC3bVDdT8OPawPW1mJUCrF6MW2OT0QLwFqCH5vNG2X7EETbX7zbVw8MUj6qPZmBm412HLdeLLUdKlxJINfoLknsVNE8BQ/mcCChde94/aFWRiAUIA=");

        assertArrayEquals(_p1, c.chacha20Decrypt(_k1, i1c, chachaOut1, 0, chachaOut1.length));
        assertArrayEquals(_p2, c.chacha20Decrypt(_k2, i2c, chachaOut2, 0, chachaOut2.length));
    }

    @Test
    public void hashedStreamTest() {
        byte[] hashedOut1 = Base64.getDecoder().decode("AAAAADiyYVkaJsQOum01HOPC02SsOjzUK1u2NoeEY7ge8cV5AAIAABGALf+7IYHO/c7GAKdUwyb5b8S6nY6kOwWsigay4Q9lLFa7fhvZosuvFcJSQ3AAcxhhiHGKkiyD2/L6D5Z7HBy/YNRQmUQLH835C4jMUveUrBftUFie25kpN6Io3pM0M/ilkuKbr9rTVmikkYakt4n6ZWJ/jcvEIYU6J2Gi4kE5xNePJr8V+f08Gvrw+UkShYAZLngxtaUs4XFdYYh5MXMmasyvFZDJ5WxlQnPR0yc7J6HhibPICA8xYkVOt5d1w+mGyY99Y3DvT0kLy3IyWw1KITnml6jAXmK9fbJKey3U8H+KSwmYvsMx8TlqvDyc/wc4BJZejitBxmssv+W9pNQbN9vzpxAEsWN1tKZuVaElIH2rEneXdmFTSYWea/7edExlT4VgqVf2M1Iy6NqF0nHJBp5nEZJdhMB6oF6LZkZkl0BZCQYcxXcmtN4kZI6GzXYT1GRfdmK6B8rF5gn5a80MzlCaK8hqrUEnQVyzOCAy89Lnd5LiBCHdnwE7V95uLEgRGJU97KKuqSYiODQGBs+qkvI3EvQ7KsovvYvHL1ZiuRUToSCK9QcvOc1rv8zt1pgykMTsNxpU1u7LDi4W5nnQv34f8mWvIJ3qB9gmz2r+QebzlJ6SdoL6v8sxv+bYGVJUm/9NzuQzg3AmAi9BLQaEzMxII1LbPkn7JDKZfWC2AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");
        byte[] hashedOut2 = Base64.getDecoder().decode("AAAAAD/aHzdwc3B0tZjLmgO5s/p9qRMWYDenqWtXcsV4mkzhAAIAAKhroNXPbpuB+IVZ17NfyVAlCx36gxH9N/KU1sJKkb/LiuGoPhHENaHUb0g1AftlvI71PjSP11KXbmjiO5jZN2fGjkzStos+YdV8JhPJyDb3LhkzVFKLO7KPEdCo4foJ+jjgb3KukwYCt91fE7E+zqUy6w1+puIUOlKZQ6W7ln/bcivb6FjDSJsTMJ11KycBUEIqdvbsi1RVyzQgFE9gRyBeg6GFY+ZNbqJyanVFnw4qmPJikR+J7ufXhRwkozRLs+l8FqiGfO1c3AdTeiDeDysl9Xtd/bUA1JS5rd3JKctuJreMyYlmpBwEBrQYNnTH+XXw/q247rUze0ITzM4QkrM85FNoUkaivlBfWPcB6J4g8rRn2SodtjgCWE1HU9hO9HMA21EgXqcvTT9dWJa9MpOj8tkaqbiJHy4bZvn5W2t4EWOEAA1NAJMNOIzqwF2hRCa6o2D+M0u6d7siBPitNfHU5EcyOTKGVvJGDHAsnl/QeSLSP7gLet0YyYhRKvubXwKaFtsWbwrzM01tuCfajthcUorW2vY5yGppGXCpNCv2qq1ukYiDugoX3wtqnsK2Pjuw9NhxxIQLYU5xrFaaSv8hdg15a/xQ2JeAvvvrziqos9o0+T9TheYoYjA6Eg6zfZUMSSe0PNI+XxxA8QWIIJIjyfl7ZVC/zfEnUQnMFsaJAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");

        assertArrayEquals(_p1, c.decodeHashedBlockStream(hashedOut1, 0));
        assertArrayEquals(_p2, c.decodeHashedBlockStream(hashedOut2, 0));
    }

    @Test
    public void hmacStreamTest() {
        byte[] k1hmac = Base64.getDecoder().decode("kPZzk8WpjrHA2EU6AkRK2EOQnP+vAlNv9jTsZsxe7Swyxp0JCuHOf5PgSfQgUDs+BfYY3n9+UY6jA5yQvCjkYQ==");
        byte[] hmacOut1 = Base64.getDecoder().decode("5tamOg0BcH7vuY79y2IH7WvaMfS5KTfLFS+imoMRZbEAAgAAEYAt/7shgc79zsYAp1TDJvlvxLqdjqQ7BayKBrLhD2UsVrt+G9miy68VwlJDcABzGGGIcYqSLIPb8voPlnscHL9g1FCZRAsfzfkLiMxS95SsF+1QWJ7bmSk3oijekzQz+KWS4puv2tNWaKSRhqS3ifplYn+Ny8QhhTonYaLiQTnE148mvxX5/Twa+vD5SRKFgBkueDG1pSzhcV1hiHkxcyZqzK8VkMnlbGVCc9HTJzsnoeGJs8gIDzFiRU63l3XD6YbJj31jcO9PSQvLcjJbDUohOeaXqMBeYr19skp7LdTwf4pLCZi+wzHxOWq8PJz/BzgEll6OK0HGayy/5b2k1Bs32/OnEASxY3W0pm5VoSUgfasSd5d2YVNJhZ5r/t50TGVPhWCpV/YzUjLo2oXScckGnmcRkl2EwHqgXotmRmSXQFkJBhzFdya03iRkjobNdhPUZF92YroHysXmCflrzQzOUJoryGqtQSdBXLM4IDLz0ud3kuIEId2fATtX3m4sSBEYlT3soq6pJiI4NAYGz6qS8jcS9Dsqyi+9i8cvVmK5FROhIIr1By85zWu/zO3WmDKQxOw3GlTW7ssOLhbmedC/fh/yZa8gneoH2CbPav5B5vOUnpJ2gvq/yzG/5tgZUlSb/03O5DODcCYCL0EtBoTMzEgjUts+SfskMpl9YLZD3lxzVUX/rIH+1VWwj2g2VFQk5mrmmz7Fw31K/eq4OgAAAAA=");
        byte[] k2hmac = Base64.getDecoder().decode("6xkIPKZBzmHCHGzOuV5OpfmtYNZGD6y0dQ9mBkQ+wmv85wkHSP+YxCe2HGISgtREtfeXD8gNG9tsU8aW28gdhA==");
        byte[] hmacOut2 = Base64.getDecoder().decode("qLgl5hEUdtMccW124ktvgTm2gvvBYiqpkuQZTU05KtoAAgAAqGug1c9um4H4hVnXs1/JUCULHfqDEf038pTWwkqRv8uK4ag+EcQ1odRvSDUB+2W8jvU+NI/XUpduaOI7mNk3Z8aOTNK2iz5h1XwmE8nINvcuGTNUUos7so8R0Kjh+gn6OOBvcq6TBgK33V8TsT7OpTLrDX6m4hQ6UplDpbuWf9tyK9voWMNImxMwnXUrJwFQQip29uyLVFXLNCAUT2BHIF6DoYVj5k1uonJqdUWfDiqY8mKRH4nu59eFHCSjNEuz6XwWqIZ87VzcB1N6IN4PKyX1e139tQDUlLmt3ckpy24mt4zJiWakHAQGtBg2dMf5dfD+rbjutTN7QhPMzhCSszzkU2hSRqK+UF9Y9wHoniDytGfZKh22OAJYTUdT2E70cwDbUSBepy9NP11Ylr0yk6Py2RqpuIkfLhtm+flba3gRY4QADU0Akw04jOrAXaFEJrqjYP4zS7p3uyIE+K018dTkRzI5MoZW8kYMcCyeX9B5ItI/uAt63RjJiFEq+5tfApoW2xZvCvMzTW24J9qO2FxSitba9jnIamkZcKk0K/aqrW6RiIO6ChffC2qewrY+O7D02HHEhAthTnGsVppK/yF2DXlr/FDYl4C+++vOKqiz2jT5P1OF5ihiMDoSDrN9lQxJJ7Q80j5fHEDxBYggkiPJ+XtlUL/N8SdRCcwWxon9wJ2pzfK02Ch8OiDBs+KBa5aRfUs/LM0sYl105mz9GQAAAAA=");

        assertArrayEquals(_p1, c.decodeHmacBlockStream(k1hmac, hmacOut1, 0));
        assertArrayEquals(_p2, c.decodeHmacBlockStream(k2hmac, hmacOut2, 0));
    }

    @Test
    public void hmacsha256Test() {
        byte[] k1h = Base64.getDecoder().decode("iV5SstxEPBhGUvjzrt3jRRxlQXLbwXY4JLCQJJ07rXi7t18AHJ6Hs3KIsa9DWMimuwji75cTgMfoGo4ssxh6Cg==");
        byte[] k2h = Base64.getDecoder().decode("pIA49n3jKH3djQBSD8f0y+jpaJVZvuCnNpcYAhBb/1kOpwrDH9Eo2N9kEQoTLrcgJcJEyq/kseafkcDmyyZtgg==");
        byte[] hmacsha256out1 = Base64.getDecoder().decode("I4tX2gT2fW/h7ZAuE9qxO97mCQ+8o5S2F/10RGmnkX8=");
        byte[] hmacsha256out2 = Base64.getDecoder().decode("nBBpW383JGK3KBhC9lHDYXgbL9Avv9EycZ0THn7fLAk=");

        assertArrayEquals(hmacsha256out1, c.hmacsha256(k1h, _p1, 0, _p1.length));
        assertArrayEquals(hmacsha256out2, c.hmacsha256(k2h, _p2, 0, _p2.length));
    }

    @Test
    public void sha256Test() {
        byte[] sha256out1 = Base64.getDecoder().decode("OLJhWRomxA66bTUc48LTZKw6PNQrW7Y2h4RjuB7xxXk=");
        byte[] sha256out2 = Base64.getDecoder().decode("P9ofN3BzcHS1mMuaA7mz+n2pExZgN6epa1dyxXiaTOE=");

        assertArrayEquals(sha256out1, c.hash(Crypto.HASH_SHA256, _p1, 0, _p1.length));
        assertArrayEquals(sha256out2, c.hash(Crypto.HASH_SHA256, _p2, 0, _p2.length));
    }

    @Test
    public void sha512Test() {
        byte[] sha512out1 = Base64.getDecoder().decode("zPAp215c2xwDJnFwN2J/3TVZlpkkAafM5EHlJ5RylhoIIKpPU6bQ5wa61a/LABGWQF0bdkeuNh5Qr+GRY9OBnw==");
        byte[] sha512out2 = Base64.getDecoder().decode("Fgm4whVZg+bQPuq2awc4jNRvMJIvVBTeuWErdTcIwiA/h3FW5FxJRYOAEbljhh+Ja56M8xI5KLJv6KzxudrTfA==");

        assertArrayEquals(sha512out1, c.hash(Crypto.HASH_SHA512, _p1, 0, _p1.length));
        assertArrayEquals(sha512out2, c.hash(Crypto.HASH_SHA512, _p2, 0, _p2.length));
    }

    @Test
    public void blake2bLongTest() {
        byte[] b2blout1 = Base64.getDecoder().decode("+nrPkHalNVB/CWHj9cebHAnZ+uoYDb8BZ3/YTVx23uOZnXu8T6M+IKg5rosf5oq96SRdk3HWpEfK");
        byte[] b2blout2 = Base64.getDecoder().decode("vM5/g3IQlLhSYnF5/BicSeNMaX+9AOBtdOxvGsOm3j01Ptx1UChuDsaQ7vr39VDgpnpEiTEd1+qaI9RCnlfT6A==");
        byte[] b2blout3 = Base64.getDecoder().decode("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");
        byte[] b2blout4 = Base64.getDecoder().decode("4ysShcdpZWq+op6TuvD4AF3h4W2es9QqfIaCagYgdooz+oPfewofBIt1aEOviKGs+K00BwCWJ61TyzaCjWU9iImgM2Id0gxcV3oibZ2ZknoZveLHF+XrI46gm5oRJO7wr6NxrqWk1rHFF4W3L1VS3vHOtnIQUqTbKuKOvJICX14oImx4Wwxg19VfRclWuyDzli7o77oQggWE0bdDbs83QqmwVNbgtpxpOEHLXZJbEBVfgXM8fnl7uHe9TKWxUiOvXvj4p/0nffqnmGfqxvEte2YUOUBkfqnlKlx2mFVF+XJcnK5dDr9uVDpjAA+wqUTidcJoNeHKqrGrx70xCfUYg3U115eoAhEVsBOaw/W7Ev9GebpwNCP9ejwMqAucJQS+T14yTfGA4FPLcVJB2dC/sSUW8BROqdmD/nutkITE/0Pv1HIBE8WfOHbHWQHV2u+jweEdP+tpk4fv43cmWcWJHAnYoLxA6RBbbUU6O9tCCDMMGKhzx3+nvtVv3T2+uAJBQ8+XjtMvDu79vqrYl1X9/Mb0qZNF57qdUQby+NiKtiwTeDeZdfpQzjtM3JCZgyzbzZAUyx/Tvc7e+9K+cZDkbisY+ia9CyDRC3SZGGxgAxTvKe4StWDX5n/74F5Rbu4yXr8S98/NKZ4FKfGSYwID+TP/Q61sdC6iPllNmD104HrNjq9vKCROsa9KPkAGRbrSkGFKfTGy7xe3Niv8pNV5yCc0R10WGyKWX3So57X4LfhxpcNnwBwpAR4kli2GT2UM1zPFHeHZobbk7WV14Yx2McI4UFEjS0+KdE57xL+1GybZyoNMwbin6jKxXQmtjjTmeSU1JWfSOMOSnlTMJWEopWNFvDzdeguFTl7CkHaLYRq+DT2B0vInu31K6Qbspm+G3svAsEb3CM8XTjWZgsGkDggdWEjrjg45ud9ZbAaSrnZlQbk91ZznfN8XkGc9yO4t9a5Qvbzosl4Zo8KW64vMqneUD/pgl34MpKEtwsT02g+L5utDSLY35LxCDtPpAWJIYYoVyAko/toE7I4u5WZz5ka6YANzjIM5sNgUB97YLRSkuycvJMBB7sLuMN02cICyf7k1UiiMtUZ+zP+Jv7D3VLd6ZX5nPY586j1poBfQK2AKBwtjJrb4YBzqbHRhQZDs07KW6cQSErwDn7ucjycMYOFRGcX6TUrMmSs/BDe4jEM2wFemPC0ltzgONvEEvzJPtO4b9MGxKx/k/sSduerx7HX3XlAYQIc+Va6PSqLz3h/aGZmxhx3FqKYLxfhXxHHiqRMhC2BO2+RhAuouzE1dfXJjWtVEnp7QnWPCuG75qmTRxHCxN6eX1bcN4FLrCIKlxhLP6jV9WYA0+NyrO6g1WQ==");

        assertArrayEquals(b2blout1, c.blake2bLong(_p1, 0, _p1.length, null, 0, 57));
        assertArrayEquals(b2blout2, c.blake2bLong(_p2, 0, _p2.length, null, 0, 64));
        assertArrayEquals(b2blout3, c.blake2bLong(_p2, 0, _p2.length, null, 0, 2401));
        assertArrayEquals(b2blout4, c.blake2bLong(_p1, 0, _p1.length, null, 0, 1024));
    }

    @Test
    public void argon2dTest() {
        // outlen = 117, pwd = _p1, salt = _p2, t_cost = 1, m_cost = 32, lanes = 1, version = 0x13
        byte[] a2dout1 = Base64.getDecoder().decode("pSnWxFB4eUtlYzvwC87Lp/c7yoYjV6VzLu4lWMXW+efYG9a6XqP7gIbw6ZlbtrNYtnP3y+ZturIz9Upg6U9Ox95h8bLY8kP0L/uaIhhoUeZIZ5nyW0KiAEAl1Geyb7gN8cWzQTmW3FBND53uR4Uw+gIuohCt");
        // outlen = 512, pwd = _p1, salt = _p2, t_cost = 4, m_cost = 16, lanes = 2, version = 0x13
        byte[] a2dout2 = Base64.getDecoder().decode("T24HzOHl3ALRE1/R06Ynoq+DFcjNEKq4X8weIoUeI/XNVju/EKhAVaPclGBnXmEGcUuaSliUEFsWTXWBByuStFtxdfG/M/OJxf/3/q9I7B7ioU029jRQFGUm5GZth1C6X5F5NGmBh+ZJlowIE0VjsPAh1KH6");

        // assertArrayEquals(a2dout1, c.argon2d(1, 32, 1, 117, _p1, _p2, null, null, 0x13));
        assertArrayEquals(a2dout2, c.argon2d(4, 16, 2, 512, _p1, _p2, null, null, 0x13));
    }
}
