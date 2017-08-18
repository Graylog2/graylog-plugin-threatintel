package org.graylog.plugins.threatintel.functions.spamhaus;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.functions.misc.LookupTableFunction;
import org.graylog.plugins.threatintel.functions.GenericLookupResult;
import org.graylog2.lookup.LookupTableService;
import org.graylog2.plugin.lookup.LookupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;

public class SpamhausIpLookupFunction extends LookupTableFunction<GenericLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(SpamhausIpLookupFunction.class);

    public static final String NAME = "spamhaus_lookup_ip";
    private static final String VALUE = "ip_address";
    private static final String LOOKUP_TABLE_NAME = "abuse-ch-ransomware-domains";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IP to look up.").build();

    private final LookupTableService.Function lookupFunction;

    @Inject
    public SpamhausIpLookupFunction(final LookupTableService lookupTableService) {
        this.lookupFunction = lookupTableService.newBuilder().lookupTable(LOOKUP_TABLE_NAME).build();
    }

    @Override
    public GenericLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to Spamhaus IP lookup.");
            return null;
        }

        LOG.debug("Running Spamhaus lookup for IP [{}].", ip);

        final LookupResult lookupResult = this.lookupFunction.lookup(ip.trim());
        if (lookupResult != null && !lookupResult.isEmpty() && lookupResult.singleValue() != null) {
            if (lookupResult.singleValue() instanceof Boolean) {
                return (Boolean)lookupResult.singleValue() ? GenericLookupResult.TRUE : GenericLookupResult.FALSE;
            }
            if (lookupResult.singleValue() instanceof String) {
                return Boolean.valueOf((String) lookupResult.singleValue()) ? GenericLookupResult.TRUE : GenericLookupResult.FALSE;
            }
        }

        return GenericLookupResult.FALSE;
    }

    @Override
    public FunctionDescriptor<GenericLookupResult> descriptor() {
        return FunctionDescriptor.<GenericLookupResult>builder()
                .name(NAME)
                .description("Match an IP address against the Spamhaus DROP and EDROP lists.")
                .params(valueParam)
                .returnType(GenericLookupResult.class)
                .build();
    }

}
