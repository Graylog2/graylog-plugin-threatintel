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
package org.graylog.plugins.threatintel.adapters.abusech;

import com.google.common.base.MoreObjects;

public enum BlocklistType {
    DOMAINS("https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt", true),
    URLS("https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt", true),
    IPS("https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt", false);

    private final String url;
    private final boolean caseInsensitive;

    BlocklistType(String url, boolean caseInsensitive) {
        this.url = url;
        this.caseInsensitive = caseInsensitive;
    }

    public String getUrl() {
        return url;
    }

    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("url", url)
                .add("caseInsensitive", caseInsensitive)
                .toString();
    }

}
