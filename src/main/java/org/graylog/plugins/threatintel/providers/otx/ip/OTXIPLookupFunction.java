package org.graylog.plugins.threatintel.providers.otx.ip;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.expressions.Expression;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupResult;
import org.graylog2.lookup.LookupTableService;
import org.graylog2.plugin.lookup.LookupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class OTXIPLookupFunction extends AbstractFunction<OTXLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(OTXIPLookupFunction.class);

    public static final String NAME = "otx_lookup_ip";
    private static final String VALUE = "ip_address";
    private static final String LOOKUP_TABLE_NAME = "otx-ip";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor
            .string(VALUE)
            .description("The IPv4 or IPv6 address to look up. Example: 198.51.100.1 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            ).build();

    private final LookupTableService.Function lookupFunction;

    @Inject
    public OTXIPLookupFunction(final LookupTableService lookupTableService) {
        this.lookupFunction = lookupTableService.newBuilder().lookupTable(LOOKUP_TABLE_NAME).build();
    }

    @Override
    public Object preComputeConstantArgument(FunctionArgs args, String s, Expression arg) {
        return arg.evaluateUnsafe(EvaluationContext.emptyContext());
    }

    @Override
    public OTXLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to OTX threat intel lookup.");
            return null;
        }

        LOG.debug("Running OTX lookup for IP [{}].", ip);

        final LookupResult lookupResult = this.lookupFunction.lookup("IPv4/" + ip.trim());
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

    @Override
    public FunctionDescriptor<OTXLookupResult> descriptor() {
        return FunctionDescriptor.<OTXLookupResult>builder()
                .name(NAME)
                .description("Look up AlienVault OTX threat intelligence data for an IPv4 or IPv6 address.")
                .params(valueParam)
                .returnType(OTXLookupResult.class)
                .build();
    }

}
