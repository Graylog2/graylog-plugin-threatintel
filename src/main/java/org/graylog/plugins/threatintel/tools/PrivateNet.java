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
import org.jboss.netty.handler.ipfilter.CIDR;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class PrivateNet {

    private static CIDR UNIQUE_LOCAL_ADDR_MASK = null;
    static {
        try {
            // RFC 4193: https://tools.ietf.org/html/rfc4193#section-3.1
            UNIQUE_LOCAL_ADDR_MASK = CIDR.newCIDR("FC00::/7");
        } catch (UnknownHostException ignored) {
        }

    }
   /**
     * Checks if an IP address is part of a private network as defined in RFC 1918 (for IPv4) and RFC 4193 (for IPv6).
    *
     *
     * @param ip The IP address to check
     * @return
     */
    public static boolean isInPrivateAddressSpace(String ip) {
        InetAddress inetAddress = InetAddresses.forString(ip);
        if (inetAddress instanceof Inet6Address) {
            // Inet6Address#isSiteLocalAddress is wrong: it only checks for FEC0:: prefixes, which is deprecated in RFC 3879
            // instead we need to check for unique local addresses, which are in FC00::/7 (in practice assigned are in FD00::/8,
            // but the RFC allows others in the future)
            return UNIQUE_LOCAL_ADDR_MASK.contains(inetAddress);
        }
        return inetAddress.isSiteLocalAddress();
    }

}

