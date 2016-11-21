package org.graylog.plugins.threatintel.providers.global.domain;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.global.GlobalLookupProvider;
import org.graylog.plugins.threatintel.providers.global.GlobalLookupResult;
import org.graylog.plugins.threatintel.tools.Domain;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GlobalDomainLookupFunction extends AbstractFunction<GlobalLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalDomainLookupFunction.class);

    public static final String NAME = "threat_intel_lookup_domain";
    private static final String VALUE = "domain_name";
    private static final String PREFIX = "prefix";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The domain to look up. Example: foo.example.org (A trailing dot ('.') will be ignored.)").build();
    private final ParameterDescriptor<String, String> prefixParam = ParameterDescriptor.string(PREFIX).description("A prefix for results. For example \"src\" will result in fields called \"src_threat_indicated\".").build();

    private final GlobalLookupProvider provider = GlobalLookupProvider.getInstance();

    @Inject
    public GlobalDomainLookupFunction(final ClusterConfigService clusterConfigService,
                                  final MetricRegistry metricRegistry) {
        provider.initialize(metricRegistry);
    }

    @Override
    public GlobalLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String domain = valueParam.required(args, context);
        String prefix = prefixParam.required(args, context);

        if (domain == null) {
            LOG.error("NULL value parameter passed to global domain lookup.");
            return null;
        }

        if (prefix == null) {
            LOG.error("NULL prefix parameter passed to global domain lookup.");
            return null;
        }

        domain = Domain.prepareDomain(domain);

        LOG.debug("Running global lookup for domain [{}] with prefix [{}].", domain, prefix);

        try {
            return provider.lookupDomain(domain.trim(), prefix.trim());
        } catch (Exception e) {
            LOG.error("Could not run global lookup for domain [{}] with prefix [{}].", domain, prefix, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<GlobalLookupResult> descriptor() {
        return FunctionDescriptor.<GlobalLookupResult>builder()
                .name(NAME)
                .description("Match a domain name against all enabled threat intel sources. (except OTX)")
                .params(valueParam, prefixParam)
                .returnType(GlobalLookupResult.class)
                .build();
    }

}
