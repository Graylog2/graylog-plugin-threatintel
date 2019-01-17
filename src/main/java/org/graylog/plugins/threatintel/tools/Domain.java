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

public class Domain {

    public static String prepareDomain(final String domain) {
        // A typical issue is regular expressions that also capture a whitespace at the beginning or the end.
        String trimmedDomain = domain.trim();

        // Some systems will capture DNS requests with a trailing '.'. Remove that for the lookup.
        if(trimmedDomain.endsWith(".")) {
            trimmedDomain = trimmedDomain.substring(0, trimmedDomain.length()-1);
        }

        return trimmedDomain;
    }

}
