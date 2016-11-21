package org.graylog.plugins.threatintel.providers.otx.domain;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupProvider;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupResult;
import org.graylog.plugins.threatintel.tools.Domain;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OTXDomainLookupFunction extends AbstractFunction<OTXLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(OTXDomainLookupFunction.class);

    public static final String NAME = "otx_lookup_domain";
    private static final String VALUE = "domain_name";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The domain to look up. Example: foo.example.org (A trailing dot ('.') will be ignored.)").build();

    private final OTXLookupProvider provider;

    @Inject
    public OTXDomainLookupFunction(final ClusterConfigService clusterConfigService,
                                   final MetricRegistry metricRegistry) {
        OTXDomainLookupProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = OTXDomainLookupProvider.getInstance();
    }

    private OTXDomainLookupFunction() {
        this.provider = null;
    }

    /**
     * Useful for testing.
     *
     * @return the function but without an initialized lookup provider or any dependencies.
     */
    public static OTXDomainLookupFunction buildStateless() {
        return new OTXDomainLookupFunction();
    }

    @Override
    public OTXLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String domain = valueParam.required(args, context);
        if (domain == null) {
            LOG.error("NULL parameter passed to OTX threat intel lookup.");
            return null;
        }

        domain = Domain.prepareDomain(domain);

        LOG.debug("Running OTX lookup for domain [{}].", domain);

        try {
            return provider.lookup(domain);
        } catch (Exception e) {
            LOG.error("Could not lookup OTX threat intelligence for domain [{}].", domain, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<OTXLookupResult> descriptor() {
        return FunctionDescriptor.<OTXLookupResult>builder()
                .name(NAME)
                .description("Look up AlienVault OTX threat intelligence data for a domain name.")
                .params(valueParam)
                .returnType(OTXLookupResult.class)
                .build();
    }

}
