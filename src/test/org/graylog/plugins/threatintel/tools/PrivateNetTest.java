package org.graylog.plugins.threatintel.tools;

import org.junit.Test;

import static org.junit.Assert.*;

public class PrivateNetTest {

    @Test
    public void testIsInPrivateAddressSpace() throws Exception {
        assertTrue(PrivateNet.isInPrivateAddressSpace("10.0.0.1"));
        assertTrue(PrivateNet.isInPrivateAddressSpace("172.16.20.50"));
        assertTrue(PrivateNet.isInPrivateAddressSpace("192.168.1.1"));
        assertFalse(PrivateNet.isInPrivateAddressSpace("99.42.44.219"));
    }

}