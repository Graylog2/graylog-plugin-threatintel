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
package org.graylog.plugins.threatintel.functions.otx;

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

            // Indicator that threat intelligence was returned for the query.
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

    public OTXLookupResult(ImmutableMap<String, Object> fields) {
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
                .put("otx_threat_indicated", false)
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
