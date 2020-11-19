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
package org.graylog.plugins.threatintel.whois.ip.parsers;

public class ARINResponseParser extends WhoisParser {

    private NetworkType prevNetworkType = null;
    private NetworkType currNetworkType = null;

    @Override
    public void readLine(String line) {
        if (line.startsWith("#") || line.isEmpty()) {
            return;
        }

        // In some cases, ARIN may have multiple results with different NetType values.  When that happens,
        //  we want to use the data from the entry with the data closest to the customer actually using the IP.
        if (line.startsWith("NetType:")) {
            prevNetworkType = currNetworkType;
            currNetworkType = NetworkType.getEnum(lineValue(line));
            if (null != currNetworkType && currNetworkType.isMoreSpecificThan(prevNetworkType)) {
                this.organization = null;
                this.countryCode = null;
            }
        }

        if((line.startsWith("Organization:") || line.startsWith("Customer:")) && this.organization == null) {
            this.organization = lineValue(line);
        }

        if(line.startsWith("Country:") && this.countryCode == null) {
            this.countryCode = lineValue(line);
        }

        if(line.startsWith("ResourceLink") && !line.contains("http")) {
            this.isRedirect = true;
            registryRedirect = findRegistryFromWhoisServer(lineValue(line));
        }
    }

    @Override
    public String buildQueryForIp(String ip) {
        // This query ensures that we get all of the records when there are multiple results rather than just a list of
        //  record summaries without details.
        return "n + " + ip;
    }

    private enum NetworkType {
        // Network types are defined in ARIN's documentation: https://www.arin.net/resources/registry/whois/#network
        // Arranged in order of decreasing preference.  Do not reorder unless preference order changes
        REASSIGNED("Reassigned"),
        DIRECT_ASSIGNMENT("Direct Assignment"),
        REALLOCATED("Reallocated"),
        DIRECT_ALLOCATION("Direct Allocation");

        private String displayName;

        NetworkType(String displayName) { this.displayName = displayName; }

        String displayName() { return displayName; }

        boolean isMoreSpecificThan(NetworkType netType) {
            if (null == netType) {
                return true;
            }
            return (this.ordinal() < netType.ordinal());
        }

        static NetworkType getEnum(String value) {
            for (NetworkType v : values()) {
                if (value.equalsIgnoreCase(v.displayName())) {
                    return v;
                }
            }
            return null;
        }
    }
}
