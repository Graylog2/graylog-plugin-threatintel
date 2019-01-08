package org.graylog.plugins.threatintel.functions.tor;

import org.apache.logging.log4j.util.Strings;
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

public class TorExitNodeLookupFunction extends LookupTableFunction<GenericLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(TorExitNodeLookupFunction.class);

    public static final String NAME = "tor_lookup";
    private static final String VALUE = "ip_address";
    private static final String LOOKUP_TABLE_NAME = "tor-exit-node-list";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IP to look up.").build();

    private final LookupTableService.Function lookupFunction;

    @Inject
    public TorExitNodeLookupFunction(final LookupTableService lookupTableService) {
        this.lookupFunction = lookupTableService.newBuilder().lookupTable(LOOKUP_TABLE_NAME).build();
    }

    @Override
    public GenericLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to Tor exit node lookup.");
            return null;
        }

        LOG.debug("Running Tor exit node lookup for IP [{}].", ip);

        final LookupResult lookupResult = this.lookupFunction.lookup(ip.trim());
        if (lookupResult != null && !lookupResult.isEmpty()) {

            // If not a String, then fall through to false at the end of the method.
            final Object value = lookupResult.singleValue();
            if (value instanceof String) {
                return Strings.isNotBlank((String) value) ? GenericLookupResult.TRUE : GenericLookupResult.FALSE;
            }
        }

        return GenericLookupResult.FALSE;
    }

    @Override
    public FunctionDescriptor<GenericLookupResult> descriptor() {
        return FunctionDescriptor.<GenericLookupResult>builder()
                .name(NAME)
                .description("Match an IP address against known Tor exit nodes to identify connections from the Tor network.")
                .params(valueParam)
                .returnType(GenericLookupResult.class)
                .build();
    }

}
