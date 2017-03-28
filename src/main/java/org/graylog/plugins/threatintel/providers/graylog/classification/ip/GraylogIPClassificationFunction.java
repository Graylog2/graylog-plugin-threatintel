package org.graylog.plugins.threatintel.providers.graylog.classification.ip;

import com.codahale.metrics.MetricRegistry;
import com.google.inject.Inject;
import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.AbstractFunction;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog.plugins.threatintel.providers.graylog.classification.GraylogClassificationResult;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GraylogIPClassificationFunction extends AbstractFunction<GraylogClassificationResult> {

    private static final Logger LOG = LoggerFactory.getLogger(GraylogIPClassificationFunction.class);

    public static final String NAME = "graylog_classify_ip";
    private static final String VALUE = "ip_address";

    private final GraylogIPClassificationProvider provider;

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor.string(VALUE).description("The IP address to classify.").build();

    @Inject
    public GraylogIPClassificationFunction(final ClusterConfigService clusterConfigService,
                                    final MetricRegistry metricRegistry) {
        GraylogIPClassificationProvider.getInstance().initialize(clusterConfigService, metricRegistry);

        this.provider = GraylogIPClassificationProvider.getInstance();
    }

    @Override
    public GraylogClassificationResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to Graylog IP classification.");
            return null;
        }

        LOG.debug("Running Graylog IP classification for IP [{}].", ip);

        try {
            return provider.lookup(ip.trim(), false);
        } catch (Exception e) {
            LOG.error("Could not run Graylog IP classification for IP [{}].", ip, e);
            return null;
        }
    }

    @Override
    public FunctionDescriptor<GraylogClassificationResult> descriptor() {
        return FunctionDescriptor.<GraylogClassificationResult>builder()
                .name(NAME)
                .description("Classify an IP address using the Graylog classification services. If a classification matches, you will get information about " +
                        "the nature of the owner of the IP address. For example if it is a public hosting service or a files haring service like Dropbox. " +
                        "Refer to the README for more details and usage instructions.")
                .params(valueParam)
                .returnType(GraylogClassificationResult.class)
                .build();
    }

}

