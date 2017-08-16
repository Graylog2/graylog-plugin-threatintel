package org.graylog.plugins.threatintel.providers.global.domain;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.DomainFunctions;
import org.graylog.plugins.threatintel.misc.functions.LookupTableFunction;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog.plugins.threatintel.providers.global.GlobalLookupResult;
import org.graylog.plugins.threatintel.tools.Domain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class GlobalDomainLookupFunction extends AbstractFunction<GlobalLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalDomainLookupFunction.class);

    public static final String NAME = "threat_intel_lookup_domain";
    private static final String VALUE = "domain_name";
    private static final String PREFIX = "prefix";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The domain to look up. Example: foo.example.org (A trailing dot ('.') will be ignored.)").build();
    private final ParameterDescriptor<String, String> prefixParam = ParameterDescriptor.string(PREFIX).description("A prefix for results. For example \"src\" will result in fields called \"src_threat_indicated\".").build();

    private Map<String, LookupTableFunction<? extends GenericLookupResult>> domainFunctions;

    @Inject
    public GlobalDomainLookupFunction(@DomainFunctions final Map<String, LookupTableFunction<? extends GenericLookupResult>> domainFunctions) {
        this.domainFunctions = domainFunctions;
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

        final List<String> matches = this.domainFunctions.entrySet()
                .stream()
                .map(entry -> {
                    final GenericLookupResult result = entry.getValue().evaluate(args, context);
                    return result.isMatch() ? entry.getKey() : null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        return GlobalLookupResult.fromMatches(matches, prefix.trim());
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
