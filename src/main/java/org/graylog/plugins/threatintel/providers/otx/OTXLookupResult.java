package org.graylog.plugins.threatintel.providers.otx;

import com.google.common.base.Joiner;
import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

public class OTXLookupResult extends ForwardingMap<String, Object> {

    private final ImmutableMap<String, Object> results;

    public static final OTXLookupResult EMPTY = new EmptyOTXLookupResult();
    public static final OTXLookupResult FALSE = new FalseOTXLookupResult();

    public static OTXLookupResult buildFromIntel(OTXIntel intel) {
        if(intel.getPulseCount() > 0) {
            ImmutableMap.Builder<String, Object> builder = ImmutableMap.<String, Object>builder();

            // Indicator that we threat intelligence was returned for the query.
            builder.put("otx_threat_indicated", true);

            // Add metadata.
            Joiner joiner = Joiner.on(", ").skipNulls();
            builder.put("otx_threat_ids", joiner.join(intel.getPulseIds()));
            builder.put("otx_threat_names", joiner.join(intel.getPulseNames()));

            return new OTXLookupResult(builder.build());
        } else {
            return OTXLookupResult.FALSE;
        }
    }

    private OTXLookupResult(ImmutableMap<String, Object> fields) {
        this.results = fields;
    }

    public Map<String, Object> getResults() {
        return results;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

    private static class FalseOTXLookupResult extends OTXLookupResult {
        private static final ImmutableMap<String, Object> EMPTY = ImmutableMap.<String, Object>builder()
                .put("otx_threat_matches", false)
                .build();

        private FalseOTXLookupResult() {
            super(EMPTY);
        }
    }

    private static class EmptyOTXLookupResult extends OTXLookupResult {
        private static final ImmutableMap<String, Object> EMPTY = ImmutableMap.<String, Object>builder().build();

        private EmptyOTXLookupResult() {
            super(EMPTY);
        }
    }
}
