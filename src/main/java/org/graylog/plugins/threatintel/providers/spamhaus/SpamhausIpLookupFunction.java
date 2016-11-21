package org.graylog.plugins.threatintel.providers.spamhaus;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SpamhausIpLookupFunction extends AbstractFunction<GenericLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(SpamhausIpLookupFunction.class);

    public static final String NAME = "spamhaus_lookup_ip";
    private static final String VALUE = "ip_address";

    private final SpamhausIpLookupProvider provider;

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IP to look up.").build();

    @Inject
    public SpamhausIpLookupFunction(final ClusterConfigService clusterConfigService,
                                     final MetricRegistry metricRegistry) {
        SpamhausIpLookupProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = SpamhausIpLookupProvider.getInstance();
    }

    @Override
    public GenericLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to Spamhaus IP lookup.");
            return null;
        }

        LOG.debug("Running Spamhaus lookup for IP [{}].", ip);

        try {
            return provider.lookup(ip.trim(), false);
        } catch (Exception e) {
            LOG.error("Could not run Spamhaus lookup for IP [{}].", ip, e);
            return null;
        }
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
