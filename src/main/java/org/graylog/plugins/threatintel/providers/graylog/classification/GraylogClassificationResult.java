package org.graylog.plugins.threatintel.providers.graylog.classification;

import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

public class GraylogClassificationResult extends ForwardingMap<String, Object> {

    private final ImmutableMap<String, Object> results;

    private static final String HIT_KEY = "classification_match";

    public static final GraylogClassificationResult FALSE = new GraylogClassificationResult.NoMatchResult();

    public static GraylogClassificationResult buildFromClassification(GraylogIPClassification classification) {
        ImmutableMap.Builder<String, Object> builder = ImmutableMap.<String, Object>builder();

        // TODO align keys.
        builder.put(HIT_KEY, true);
        builder.put("classification_name", classification.name);
        builder.put("classification_id", classification.shortname);
        builder.put("classification_cidr", classification.cidr);
        builder.put("classification_type", classification.classification);

        return new GraylogClassificationResult(builder.build());
    }

    private GraylogClassificationResult(ImmutableMap<String, Object> fields) {
        this.results = fields;
    }

    public Map<String, Object> getResults() {
        return results;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

    private static class NoMatchResult extends GraylogClassificationResult {
        private static final ImmutableMap<String, Object> EMPTY = ImmutableMap.<String, Object>builder()
                .put(HIT_KEY, false)
                .build();

        private NoMatchResult() {
            super(EMPTY);
        }
    }

}
