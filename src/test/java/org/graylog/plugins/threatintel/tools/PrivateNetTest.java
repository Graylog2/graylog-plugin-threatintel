/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
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