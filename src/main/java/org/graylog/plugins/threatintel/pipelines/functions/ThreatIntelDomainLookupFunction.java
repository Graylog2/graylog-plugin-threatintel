package org.graylog.plugins.threatintel.pipelines.functions;

import com.google.common.collect.ForwardingMap;
import com.google.common.collect.ImmutableMap;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.expressions.Expression;
import org.graylog.plugins.pipelineprocessor.ast.functions.Function;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;

import java.util.Map;

public class ThreatIntelDomainLookupFunction implements Function<ThreatIntelDomainLookupFunction.LookupResult> {

    public static final String NAME = "threat_intel_lookup_domain";

    private static final String VALUE = "domain_name";

    @Override
    public Object preComputeConstantArgument(FunctionArgs args, String s, Expression arg) {
        return arg.evaluateUnsafe(EvaluationContext.emptyContext());
    }

    @Override
    public LookupResult evaluate(FunctionArgs functionArgs, EvaluationContext evaluationContext) {
        return new LookupResult();
    }

    @Override
    public FunctionDescriptor descriptor() {
        return FunctionDescriptor.builder()
                .name(NAME)
                .description("Look up threat intelligence data for a domain name.")
                .params(ParameterDescriptor.string(VALUE).description("The domain to look up. Example: example.org").build())
                .returnType(LookupResult.class)
                .build();
    }

    public static class LookupResult extends ForwardingMap<String, String> {

        private final ImmutableMap<String, String> results;

        public LookupResult() {
            ImmutableMap.Builder<String, String> builder = ImmutableMap.<String, String>builder();

            builder.put("superfoo", "superbar");

            this.results = builder.build();
        }


        public Map<String, String> getResults() {
            return results;
        }

        @Override
        protected Map<String, String> delegate() {
            return getResults();
        }

    }

}
