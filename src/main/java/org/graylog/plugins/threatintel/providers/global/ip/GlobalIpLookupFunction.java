package org.graylog.plugins.threatintel.providers.global.ip;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.IPFunctions;
import org.graylog.plugins.threatintel.misc.functions.LookupTableFunction;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog.plugins.threatintel.providers.global.GlobalLookupResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class GlobalIpLookupFunction extends AbstractFunction<GlobalLookupResult> {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalIpLookupFunction.class);

    public static final String NAME = "threat_intel_lookup_ip";
    private static final String VALUE = "ip";
    private static final String PREFIX = "prefix";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IPv4 or IPv6 address to look up.").build();
    private final ParameterDescriptor<String, String> prefixParam = ParameterDescriptor.string(PREFIX).description("A prefix for results. For example \"src_addr\" will result in fields called \"src_addr_threat_indicated\".").build();

    private Map<String, LookupTableFunction<? extends GenericLookupResult>> ipFunctions;

    @Inject
    public GlobalIpLookupFunction(@IPFunctions final Map<String, LookupTableFunction<? extends GenericLookupResult>> ipFunctions) {
        this.ipFunctions = ipFunctions;
    }

    @Override
    public GlobalLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        String prefix = prefixParam.required(args, context);

        if (ip == null) {
            LOG.error("NULL value parameter passed to global IP lookup.");
            return null;
        }

        if (prefix == null) {
            LOG.error("NULL prefix parameter passed to global IP lookup.");
            return null;
        }

        LOG.debug("Running global lookup for IP [{}] with prefix [{}].", ip, prefix);

        final List<String> matches = this.ipFunctions.entrySet()
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
                .description("Match an IP address against all enabled threat intel sources. (except OTX)")
                .params(valueParam, prefixParam)
                .returnType(GlobalLookupResult.class)
                .build();
    }

}
