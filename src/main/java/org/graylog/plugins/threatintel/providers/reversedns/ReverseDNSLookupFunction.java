package org.graylog.plugins.threatintel.providers.reversedns;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ReverseDNSLookupFunction extends AbstractFunction<String> {

    private static final Logger LOG = LoggerFactory.getLogger(ReverseDNSLookupFunction.class);

    public static final String NAME = "reverse_dns";
    private static final String VALUE = "ip_address";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IPv4 or IPv6 address to look up.").build();

    private ReverseDNSLookupProvider provider = ReverseDNSLookupProvider.getInstance();

    @Inject
    public ReverseDNSLookupFunction(final MetricRegistry metricRegistry) {
        provider.initialize(metricRegistry);
    }

    @Override
    public String evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);

        if (ip == null) {
            LOG.error("NULL parameter passed to reverse DNS lookup.");
            return null;
        }

        LOG.debug("Running reverse DNS lookup for IP [{}].", ip);

        try {
            String result = provider.lookup(ip);
            return result;
        } catch (Exception e) {
            LOG.error("Could not run reverse DNS lookup for IP [{}].", ip, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<String> descriptor() {
        return FunctionDescriptor.<String>builder()
                .name(NAME)
                .description("Reverse DNS lookup an IP address. This will return the passed IP address if no hostname could be resolved.")
                .params(valueParam)
                .returnType(String.class)
                .build();
    }

}
