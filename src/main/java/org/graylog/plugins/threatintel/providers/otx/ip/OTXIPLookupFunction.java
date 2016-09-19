package org.graylog.plugins.threatintel.providers.otx.ip;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.expressions.Expression;
import org.graylog.plugins.pipelineprocessor.ast.functions.Function;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupProvider;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupResult;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OTXIPLookupFunction implements Function<OTXLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(OTXIPLookupFunction.class);

    public static final String NAME = "otx_lookup_ip";
    private static final String VALUE = "ip_address";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor
            .string(VALUE)
            .description("The IPv4 or IPv6 address to look up. Example: 198.51.100.1 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            ).build();

    private final OTXLookupProvider provider;

    @Inject
    public OTXIPLookupFunction(final ClusterConfigService clusterConfigService,
                               final MetricRegistry metricRegistry) {
        OTXIPLookupProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = OTXIPLookupProvider.getInstance();
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

        try {
            return provider.lookup(ip);
        } catch (Exception e) {
            LOG.error("Could not lookup OTX threat intelligence for IP [{}].", ip, e);
            return null;
        }
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
