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

    @Override
    public void readLine(String line) {
        if (line.startsWith("#") || line.isEmpty()) {
            return;
        }

        if(line.startsWith("Organization:") && this.organization == null) {
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

}
