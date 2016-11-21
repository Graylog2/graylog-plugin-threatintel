package org.graylog.plugins.threatintel.providers.abusech.ip;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog.plugins.threatintel.providers.abusech.AbuseChRansomLookupProvider;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AbuseChRansomIpLookupFunction extends AbstractFunction<GenericLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(AbuseChRansomIpLookupFunction.class);

    public static final String NAME = "abusech_ransom_lookup_ip";
    private static final String VALUE = "ip_address";

    private final AbuseChRansomLookupProvider provider;

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IPv4 or IPv6 address to look up. Example: 198.51.100.1 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334").build();

    @Inject
    public AbuseChRansomIpLookupFunction(final ClusterConfigService clusterConfigService,
                                         final MetricRegistry metricRegistry) {
        AbuseChRansomLookupProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = AbuseChRansomLookupProvider.getInstance();
    }

    @Override
    public GenericLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to abuse.ch Ransomware IP lookup.");
            return null;
        }

        LOG.debug("Running abuse.ch Ransomware lookup for IP [{}].", ip);

        try {
            return provider.lookup(ip.trim(), false);
        } catch (Exception e) {
            LOG.error("Could not run abuse.ch Ransomware lookup lookup for IP [{}].", ip, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<GenericLookupResult> descriptor() {
        return FunctionDescriptor.<GenericLookupResult>builder()
                .name(NAME)
                .description("Match a IPv4 or IPv6 address against the abuse.ch Ransomware IP Blocklist. (RW_IPBL)")
                .params(valueParam)
                .returnType(GenericLookupResult.class)
                .build();
    }

}
