package org.graylog.plugins.threatintel.whois.ip;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WhoisLookupIpFunction extends AbstractFunction<WhoisIpLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(WhoisLookupIpFunction.class);

    public static final String NAME = "whois_lookup_ip";
    private static final String VALUE = "ip_address";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IPv4 or IPv6 address to look up.").build();

    private WhoisIpLookupProvider provider = WhoisIpLookupProvider.getInstance();

    @Inject
    public WhoisLookupIpFunction(final ClusterConfigService clusterConfigService,
                                    final MetricRegistry metricRegistry) {
        provider.initialize(metricRegistry);
    }

    @Override
    public WhoisIpLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to WHOIS IP lookup.");
            return null;
        }

        LOG.debug("Running WHOIS lookup for IP [{}].", ip);

        try {
            return provider.lookup(ip);
        } catch (Exception e) {
            LOG.error("Could not run WHOIS lookup for IP [{}].", ip, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<WhoisIpLookupResult> descriptor() {
        return FunctionDescriptor.<WhoisIpLookupResult>builder()
                .name(NAME)
                .description("Get WHOIS information of an IP address")
                .params(valueParam)
                .returnType(WhoisIpLookupResult.class)
                .build();
    }


}
