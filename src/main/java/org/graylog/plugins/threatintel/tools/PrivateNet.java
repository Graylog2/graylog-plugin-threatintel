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

import com.google.common.net.InetAddresses;

import java.net.Inet6Address;
import java.net.InetAddress;

public class PrivateNet {

   /**
     * Checks if an IPv4 address is part of a private network as defined in RFC 1918. This ignores IPv6 addresses for now and always returns false for them.
     *
     * @param ip The IPv4 address to check
     * @return
     */
    public static boolean isInPrivateAddressSpace(String ip) {
        InetAddress inetAddress = InetAddresses.forString(ip);
        if (inetAddress instanceof Inet6Address) {
            // we don't deal with IPv6 unique local addresses currently.
            return false;
        }
        return inetAddress.isSiteLocalAddress();
    }

}

