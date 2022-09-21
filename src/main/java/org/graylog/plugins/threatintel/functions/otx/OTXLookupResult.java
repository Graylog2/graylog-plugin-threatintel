/*
 * Copyright (C) 2020 Graylog, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */
package org.graylog.plugins.threatintel.functions.otx;

import com.google.common.base.Joiner;
import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;
import org.graylog2.plugin.lookup.LookupResult;

import java.util.Map;

public class OTXLookupResult extends ForwardingMap<String, Object> {

    public static final String LOOKUP_KEY = "key";
    public static final String MESSAGE = "message";
    public static final String HAS_ERROR = "has_error";
    public static final String OTX_THREAT_INDICATED = "otx_threat_indicated";
    private final ImmutableMap<String, Object> results;

    protected static final OTXLookupResult EMPTY = new EmptyOTXLookupResult();
    protected static final OTXLookupResult FALSE = new FalseOTXLookupResult();

    public static OTXLookupResult buildFromError(LookupResult lookupResult) {
        return new FalseOTXLookupResult(
                (String) lookupResult.multiValue().get(LOOKUP_KEY),
                (String) lookupResult.multiValue().get(MESSAGE));
    }

    public static OTXLookupResult buildFromIntel(OTXIntel intel) {
        if (intel.getPulseCount() > 0) {
            ImmutableMap.Builder<String, Object> builder = ImmutableMap.<String, Object>builder();

            // Indicator that threat intelligence was returned for the query.
            builder.put(OTX_THREAT_INDICATED, true);

            // Add metadata.
            Joiner joiner = Joiner.on(", ").skipNulls();
            builder.put("otx_threat_ids", joiner.join(intel.getPulseIds()));
            builder.put("otx_threat_names", joiner.join(intel.getPulseNames()));

            return new OTXLookupResult(builder.build());
        } else {
            return OTXLookupResult.FALSE;
        }
    }

    public OTXLookupResult(ImmutableMap<String, Object> fields) {
        this.results = fields;
    }

    public Map<String, Object> getResults() {
        return results;
    }

    public boolean hasError() {
        if (results != null && !results.isEmpty()) {
            return (results.get(HAS_ERROR) != null);
        }
        return false;
    }

    @Override
    protected Map<String, Object> delegate() {
        return getResults();
    }

    private static class FalseOTXLookupResult extends OTXLookupResult {
        private static final ImmutableMap<String, Object> EMPTY = ImmutableMap.<String, Object>builder()
                .put(OTX_THREAT_INDICATED, false)
                .build();

        private FalseOTXLookupResult() {
            super(EMPTY);
        }

        private FalseOTXLookupResult(String key, String errMsg) {
            super(ImmutableMap.<String, Object>builder()
                    .put(OTX_THREAT_INDICATED, false)
                    .put(HAS_ERROR, true)
                    .put(LOOKUP_KEY, key)
                    .put(MESSAGE, errMsg)
                    .build());
        }
    }

    private static class EmptyOTXLookupResult extends OTXLookupResult {
        private static final ImmutableMap<String, Object> EMPTY = ImmutableMap.<String, Object>builder().build();

        private EmptyOTXLookupResult() {
            super(EMPTY);
        }
    }
}
