package org.graylog.plugins.threatintel.functions.otx;

import org.graylog.plugins.pipelineprocessor.EvaluationContext;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionArgs;
import org.graylog.plugins.pipelineprocessor.ast.functions.FunctionDescriptor;
import org.graylog.plugins.pipelineprocessor.ast.functions.ParameterDescriptor;
import org.graylog2.lookup.LookupTableService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;

public class OTXIPLookupFunction extends AbstractOTXLookupFunction {

    private static final Logger LOG = LoggerFactory.getLogger(OTXIPLookupFunction.class);

    public static final String NAME = "otx_lookup_ip";
    private static final String VALUE = "ip_address";

    private final ParameterDescriptor<String, String> valueParam = ParameterDescriptor
            .string(VALUE)
            .description("The IPv4 or IPv6 address to look up. Example: 198.51.100.1 or 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
            .build();


    @Inject
    public OTXIPLookupFunction(final LookupTableService lookupTableService) {
        super(lookupTableService);
    }

    @Override
    public OTXLookupResult evaluate(FunctionArgs args, EvaluationContext context) {
        String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to OTX threat intel lookup.");
            return null;
        }

        LOG.debug("Running OTX lookup for IP [{}].", ip);

        return lookupIntel(ip.trim(), "IPv4");
    }

    @Override
    public FunctionDescriptor<OTXLookupResult> descriptor() {
        return FunctionDescriptor.<OTXLookupResult>builder()
                .name(NAME)
                .description("Look up AlienVault OTX threat intelligence data for an IPv4 or IPv6 address.")
                .params(valueParam)
                .returnType(OTXLookupResult.class)
                .build();
    }

}
