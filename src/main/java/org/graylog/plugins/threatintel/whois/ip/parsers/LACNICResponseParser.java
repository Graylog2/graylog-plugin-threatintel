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

public class LACNICResponseParser extends WhoisParser {

    @Override
    public void readLine(String line) {
        if (line.startsWith("%") || line.isEmpty()) {
            return;
        }

        if(line.startsWith("owner:") && this.organization == null) {
            this.organization = lineValue(line);
        }

        if(line.startsWith("country:") && this.countryCode == null) {
            this.countryCode = lineValue(line);
        }
    }

    @Override
    public boolean isRedirect() {
        return false; // TODO implement
    }

    @Override
    public InternetRegistry getRegistryRedirect() {
        return null; // TODO implement
    }


}
