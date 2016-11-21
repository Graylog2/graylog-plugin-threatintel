package org.graylog.plugins.threatintel.providers.global;

import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;

import java.util.List;
import java.util.Map;

public class GlobalLookupResult extends ForwardingMap<String, Object> {

    public static final String RESULTS_KEY = "threat_indicated";

    private final ImmutableMap<String, Object> results;

    private GlobalLookupResult(ImmutableMap<String, Object> fields) {
        this.results = fields;
    }

    public static GlobalLookupResult fromMatches(List<String> matches, String prefix) {
        ImmutableMap.Builder<String, Object> fields = new ImmutableMap.Builder<>();

        // False matrch
        if(matches.isEmpty()) {
            fields.put(prefixedField(prefix, RESULTS_KEY), false);
            return new GlobalLookupResult(fields.build());
        }

        fields.put(prefixedField(prefix, RESULTS_KEY), true);

        for (String match : matches) {
            // threat_indicated_spamhaus => true
            fields.put(prefixedField(prefix, RESULTS_KEY) + "_" + match, true);
        }

        return new GlobalLookupResult(fields.build());
    }

    public Map<String, Object> getResults() {
        return results;
    }

    private static String prefixedField(String prefix, String field) {
        return prefix + "_" + field;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

}