package org.graylog.plugins.threatintel.providers.tor;

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

public class TorExitNodeLookupFunction extends AbstractFunction<GenericLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(TorExitNodeLookupFunction.class);

    public static final String NAME = "tor_lookup";
    private static final String VALUE = "ip_address";

    private final TorExitNodeLookupProvider provider;

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IP to look up.").build();

    @Inject
    public TorExitNodeLookupFunction(final ClusterConfigService clusterConfigService,
                                   final MetricRegistry metricRegistry) {
        TorExitNodeLookupProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = TorExitNodeLookupProvider.getInstance();
    }

    @Override
    public GenericLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to Tor exit node lookup.");
            return null;
        }

        LOG.debug("Running Tor exit node lookup for IP [{}].", ip);

        try {
            return provider.lookup(ip.trim(), false);
        } catch (Exception e) {
            LOG.error("Could not run Tor exit node lookup for IP [{}].", ip, e);
            return null;
        }
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
