package org.graylog.plugins.threatintel.functions.otx;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.tools.Domain;
import org.graylog2.lookup.LookupTableService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;

public class OTXDomainLookupFunction extends AbstractOTXLookupFunction {

    private static final Logger LOG = LoggerFactory.getLogger(OTXDomainLookupFunction.class);

    public static final String NAME = "otx_lookup_domain";
    private static final String VALUE = "domain_name";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor
            .string(VALUE)
            .description("The domain to look up. Example: foo.example.org (A trailing dot ('.') will be ignored.)")
            .build();

    @Inject
    public OTXDomainLookupFunction(final LookupTableService lookupTableService) {
        super(lookupTableService);
    }

    @Override
    public OTXLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        final String domain = valueParam.required(args, context);
        if (domain == null) {
            LOG.error("NULL parameter passed to OTX threat intel lookup.");
            return OTXLookupResult.EMPTY;
        }

        LOG.debug("Running OTX lookup for domain [{}].", domain);
        return lookupIntel("domain", Domain.prepareDomain(domain).trim());
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
