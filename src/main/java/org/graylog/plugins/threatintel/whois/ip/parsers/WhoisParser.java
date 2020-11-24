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

import org.graylog.plugins.threatintel.whois.ip.InternetRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class WhoisParser {

    protected static final Logger LOG = LoggerFactory.getLogger(WhoisParser.class);

    protected boolean isRedirect = false;
    protected InternetRegistry registryRedirect;

    protected String organization;
    protected String countryCode;

    protected String lineValue(String line) {
        if(!line.contains(":")) {
            return "";
        }

        String[] parts = line.split(":");
        return parts[1].trim();
    }

    protected InternetRegistry findRegistryFromWhoisServer(String server) {
        for (InternetRegistry registry : InternetRegistry.values()) {
            if (registry.getWhoisServer().equals(server)) {
                return registry;
            }
        }

        LOG.error("No known internet registry for WHOIS server redirect [{}].", server);
        return null;
    }

    public String buildQueryForIp(String ip) { return ip; }

    public boolean isRedirect() {
        return isRedirect;
    }

    public InternetRegistry getRegistryRedirect() {
        return registryRedirect;
    }

    public String getOrganization() {
        return this.organization;
    }

    public String getCountryCode() {
        return this.countryCode;
    }

    public abstract void readLine(String line);

}
