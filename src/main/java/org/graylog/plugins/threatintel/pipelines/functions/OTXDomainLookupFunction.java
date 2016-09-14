package org.graylog.plugins.threatintel.pipelines.functions;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.expressions.Expression;
import org.graylog.plugins.pipelineprocessor.ast.functions.Function;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.otx.OTXDomainLookupProvider;
import org.graylog.plugins.threatintel.providers.otx.OTXLookupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;

public class OTXDomainLookupFunction implements Function<OTXLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(OTXDomainLookupFunction.class);

    public static final String NAME = "otx_lookup_domain";

    private static final String VALUE = "domain_name";

    private final OTXDomainLookupProvider provider;

    private final ParameterDescriptor<String, String> valueParam;

    public OTXDomainLookupFunction() {
        this.provider = OTXDomainLookupProvider.getInstance();
        this.valueParam = ParameterDescriptor.string(VALUE).description("The domain to look up. Example: foo.example.org").build();
    }

    @Override
    public Object preComputeConstantArgument(FunctionArgs args, String s, Expression arg) {
        return arg.evaluateUnsafe(EvaluationContext.emptyContext());
    }

    @Override
    public OTXLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        final String domain = valueParam.required(args, context);
        LOG.debug("Running OTX lookup for domain [{}].", domain);

        try {
            return OTXLookupResult.buildFromIntel(provider.lookup(domain));
        } catch (ExecutionException e) {
            LOG.error("Could not lookup OTX threat intelligence for domain [{}].", domain, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor descriptor() {
        return FunctionDescriptor.builder()
                .name(NAME)
                .description("Look up AlienVault OTX threat intelligence data for a domain name.")
                .params(valueParam)
                .returnType(OTXLookupResult.class)
                .build();
    }

}
