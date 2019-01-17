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
package org.graylog.plugins.threatintel.adapters.tor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TorExitNodeListParser {
    public Map<String, List<String>> parse(String list) {
        if (list == null) {
            return Collections.emptyMap();
        }
        final Map<String, List<String>> result = new HashMap<>();
        String exitNodeId = null;
        for (String line : list.split("\n")) {
            if (line.startsWith("ExitNode")) {
                final String elements[] = line.split("\\s+");
                if (elements.length == 2) {
                    exitNodeId = elements[1];
                }
            }
            if (line.startsWith("ExitAddress")) {
                final String elements[] = line.split("\\s+");
                if (elements.length >= 2 && exitNodeId != null) {
                    final String ip = elements[1];
                    if (!result.containsKey(ip)) {
                        result.put(ip, new ArrayList<>());
                    }
                    result.get(ip).add(exitNodeId);
                }
            }
        }
        return result;
    }
}
