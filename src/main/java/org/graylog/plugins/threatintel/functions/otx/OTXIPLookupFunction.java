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
        final String ip = valueParam.required(args, context);
        if (ip == null) {
            LOG.error("NULL parameter passed to OTX threat intel lookup.");
            return OTXLookupResult.EMPTY;
        }

        LOG.debug("Running OTX lookup for IP [{}].", ip);

        return lookupIntel(ip.trim(), detectIpType(ip.trim()));
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

    private String detectIpType(String ip) {
        /*
         * This is gonna be super stupid but the user can pass anything in here and trying to recognize IPv4 by a
         * regular expression just costs a lot of CPU cycles. We trust the user to pass in either IPv4 or IPv6 and
         * if he/she puts something else in here, it's not our problem. ¯\_(ツ)_/¯
         */
        if(ip.contains(".")) {
            return "IPv4";
        }

        /*
         * If it's not IPv4, we just expect it to be IPv6. OTX API will return
         * simply no results if its any artificial string.
         */
        return "IPv6";
    }
}
