package org.graylog.plugins.threatintel.providers.abusech.domain;

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

public class AbuseChRansomDomainLookupFunction extends AbstractFunction<GenericLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(AbuseChRansomDomainLookupFunction.class);

    public static final String NAME = "abusech_ransom_lookup_domain";
    private static final String VALUE = "domain_name";

    private final AbuseChRansomLookupProvider provider;

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The domain to look up. Example: foo.example.org (A trailing dot ('.') will be ignored.)").build();

    @Inject
    public AbuseChRansomDomainLookupFunction(final ClusterConfigService clusterConfigService,
                                    final MetricRegistry metricRegistry) {
        AbuseChRansomLookupProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = AbuseChRansomLookupProvider.getInstance();
    }

    @Override
    public GenericLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String domain = valueParam.required(args, context);
        if (domain == null) {
            LOG.error("NULL parameter passed to abuse.ch Ransomware domain lookup.");
            return null;
        }

        LOG.debug("Running abuse.ch Ransomware lookup for domain [{}].", domain);

        try {
            return provider.lookup(domain.trim());
        } catch (Exception e) {
            LOG.error("Could not run abuse.ch Ransomware lookup lookup for domain [{}].", domain, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<GenericLookupResult> descriptor() {
        return FunctionDescriptor.<GenericLookupResult>builder()
                .name(NAME)
                .description("Match a domain name against the abuse.ch Ransomware Domain Blocklist. (RW_DOMBL)")
                .params(valueParam)
                .returnType(GenericLookupResult.class)
                .build();
    }

}
