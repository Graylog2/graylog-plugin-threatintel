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
package org.graylog.plugins.threatintel.whois.ip;

public enum InternetRegistry {

    AFRINIC("whois.afrinic.net"),
    APNIC("whois.apnic.net"),
    ARIN("whois.arin.net"),
    LACNIC("whois.lacnic.net"),
    RIPENCC("whois.ripe.net");

    final String whoisServer;

    InternetRegistry(String whoisServer) {
        this.whoisServer = whoisServer;
    }

    public String getWhoisServer() {
        return whoisServer;
    }
}
