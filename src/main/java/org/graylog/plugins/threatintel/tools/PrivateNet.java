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

