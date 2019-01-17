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
import org.apache.commons.net.util.SubnetUtils;

public class PrivateNet {

    public static final SubnetUtils.SubnetInfo TEN = new SubnetUtils("10.0.0.0/8").getInfo();
    public static final SubnetUtils.SubnetInfo ONE_HUNDRED_SEVENTY_TWO = new SubnetUtils("172.16.0.0/12").getInfo();
    public static final SubnetUtils.SubnetInfo ONE_HUNDRED_NINETY_TWO = new SubnetUtils("192.168.0.0/16").getInfo();

    /**
     * Checks if an IPv4 address is part of a private network as defined in RFC 1918.
     *
     * @param ip The IPv4 address to check
     * @return
     */
    public static boolean isInPrivateAddressSpace(String ip) {
        if(!InetAddresses.isInetAddress(ip)) {
            return false;
        }

        return ONE_HUNDRED_SEVENTY_TWO.isInRange(ip) || TEN.isInRange(ip) || ONE_HUNDRED_NINETY_TWO.isInRange(ip);
    }

}

