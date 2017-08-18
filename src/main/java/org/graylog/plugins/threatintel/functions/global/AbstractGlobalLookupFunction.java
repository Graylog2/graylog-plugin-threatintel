package org.graylog.plugins.threatintel.functions.global;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration;
import org.graylog.plugins.threatintel.functions.GenericLookupResult;
import org.graylog.plugins.threatintel.functions.misc.LookupTableFunction;
import org.graylog2.plugin.cluster.ClusterConfigService;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

abstract class AbstractGlobalLookupFunction extends AbstractFunction<GlobalLookupResult> {
    final AtomicReference<ThreatIntelPluginConfiguration> config = new AtomicReference<>();

    AbstractGlobalLookupFunction(final ClusterConfigService clusterConfigService) {
        this.config.set(clusterConfigService.getOrDefault(ThreatIntelPluginConfiguration.class, ThreatIntelPluginConfiguration.defaults()));
    }

    GlobalLookupResult matchEntityAgainstFunctions(Map<String, LookupTableFunction<? extends GenericLookupResult>> functions,
                                                   FunctionArgs args,
                                                   EvaluationContext context,
                                                   String prefix) {
        final List<String> matches = functions.entrySet()
                .stream()
                .filter(f -> isEnabled(f.getValue()))
                .map(entry -> {
                    final GenericLookupResult result = entry.getValue().evaluate(args, context);
                    return result.isMatch() ? entry.getKey() : null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        return GlobalLookupResult.fromMatches(matches, prefix.trim());
    }

    abstract boolean isEnabled(LookupTableFunction<? extends GenericLookupResult> function);
}
