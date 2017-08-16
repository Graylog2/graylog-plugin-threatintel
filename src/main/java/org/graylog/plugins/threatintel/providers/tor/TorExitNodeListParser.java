package org.graylog.plugins.threatintel.providers.tor;

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
