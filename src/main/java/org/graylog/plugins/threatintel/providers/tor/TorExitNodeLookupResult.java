package org.graylog.plugins.threatintel.providers.tor;

import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

public class TorExitNodeLookupResult extends ForwardingMap<String, Object> {

    private final ImmutableMap<String, Object> results;

    public static final TorExitNodeLookupResult FALSE = new FalseTorExitNodeLookupResult();
    public static final TorExitNodeLookupResult TRUE = new TrueTorExitNodeLookupResult();

    private TorExitNodeLookupResult(ImmutableMap<String, Object> fields) {
        this.results = fields;
    }

    public Map<String, Object> getResults() {
        return results;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

    private static class FalseTorExitNodeLookupResult extends TorExitNodeLookupResult {
        private static final ImmutableMap<String, Object> FALSE = ImmutableMap.<String, Object>builder()
                .put("exit_node_indicated", false)
                .build();

        private FalseTorExitNodeLookupResult() {
            super(FALSE);
        }
    }

    private static class TrueTorExitNodeLookupResult extends TorExitNodeLookupResult {
        private static final ImmutableMap<String, Object> TRUE = ImmutableMap.<String, Object>builder()
                .put("exit_node_indicated", true)
                .build();

        private TrueTorExitNodeLookupResult() {
            super(TRUE);
        }
    }

}
