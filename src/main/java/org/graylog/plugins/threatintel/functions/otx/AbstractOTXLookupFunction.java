package org.graylog.plugins.threatintel.functions.otx;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import org.graylog.plugins.threatintel.functions.misc.LookupTableFunction;
import org.graylog2.lookup.LookupTableService;
import org.graylog2.plugin.lookup.LookupResult;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

abstract class AbstractOTXLookupFunction extends LookupTableFunction<OTXLookupResult> {
    private static final String IP_LOOKUP_TABLE_NAME = "otx-api-ip";
    private static final String DOMAIN_LOOKUP_TABLE_NAME = "otx-api-domain";
    private final LookupTableService.Function ipLookupFunction;
    private final LookupTableService.Function domainLookupFunction;

    AbstractOTXLookupFunction(final LookupTableService lookupTableService) {
        this.ipLookupFunction = lookupTableService.newBuilder().lookupTable(IP_LOOKUP_TABLE_NAME).build();
        this.domainLookupFunction = lookupTableService.newBuilder().lookupTable(DOMAIN_LOOKUP_TABLE_NAME).build();
    }

    protected OTXLookupResult lookupIP(final String ip) {
        return lookupIntel(ip, ipLookupFunction);
    }

    protected OTXLookupResult lookupDomain(final String domain) {
        return lookupIntel(domain, ipLookupFunction);
    }

    private OTXLookupResult lookupIntel(final String key, final LookupTableService.Function lookupFunction) {
        final LookupResult lookupResult = lookupFunction.lookup(key);

        if (lookupResult != null && !lookupResult.isEmpty()) {
            final ImmutableMap.Builder<String, Object> result = ImmutableMap.builder();
            final Object singleValue = lookupResult.singleValue();
            final Integer pulseCount = singleValue instanceof Integer ? (Integer)singleValue : Integer.valueOf(String.valueOf(singleValue));

            if (pulseCount > 0) {
                result.put("otx_threat_indicated", true);
                if (lookupResult.multiValue() != null && lookupResult.multiValue() instanceof List) {
                    Joiner joiner = Joiner.on(", ").skipNulls();
                    final List<Map<String, Object>> pulses = (List<Map<String, Object>>)lookupResult.multiValue();

                    final List<String> ids = pulses.stream()
                            .map(pulse -> String.valueOf(pulse.get("id")))
                            .collect(Collectors.toList());
                    result.put("otx_threat_ids", joiner.join(ids));

                    final List<String> names = pulses.stream()
                            .map(pulse -> String.valueOf(pulse.get("name")))
                            .collect(Collectors.toList());
                    result.put("otx_threat_names", joiner.join(names));
                }
                return new OTXLookupResult(result.build());
            }
            return OTXLookupResult.FALSE;

        }

        return OTXLookupResult.EMPTY;
    }
}
