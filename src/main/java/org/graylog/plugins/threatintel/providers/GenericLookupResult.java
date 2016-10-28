package org.graylog.plugins.threatintel.providers;

import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

public class GenericLookupResult extends ForwardingMap<String, Object> {

    private final ImmutableMap<String, Object> results;

    public static final GenericLookupResult FALSE = new FalseGenericLookupResult();
    public static final GenericLookupResult TRUE = new TrueGenericLookupResult();

    private GenericLookupResult(ImmutableMap<String, Object> fields) {
        this.results = fields;
    }

    public Map<String, Object> getResults() {
        return results;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

    private static class FalseGenericLookupResult extends GenericLookupResult {
        private static final ImmutableMap<String, Object> FALSE = ImmutableMap.<String, Object>builder()
                .put("threat_indicated", false)
                .build();

        private FalseGenericLookupResult() {
            super(FALSE);
        }
    }

    private static class TrueGenericLookupResult extends GenericLookupResult {
        private static final ImmutableMap<String, Object> TRUE = ImmutableMap.<String, Object>builder()
                .put("threat_indicated", true)
                .build();

        private TrueGenericLookupResult() {
            super(TRUE);
        }
    }

}
