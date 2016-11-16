package org.graylog.plugins.threatintel;

import com.google.inject.Binder;
import com.google.inject.TypeLiteral;
import com.google.inject.multibindings.MapBinder;
import org.graylog.plugins.threatintel.misc.functions.PrivateNetLookupFunction;
import org.graylog.plugins.threatintel.providers.abusech.domain.AbuseChRansomDomainLookupFunction;
import org.graylog.plugins.threatintel.providers.otx.domain.OTXDomainLookupFunction;
import org.graylog.plugins.threatintel.providers.otx.ip.OTXIPLookupFunction;
import org.graylog.plugins.threatintel.providers.spamhaus.SpamhausIpLookupFunction;
import org.graylog.plugins.threatintel.providers.tor.TorExitNodeLookupFunction;
import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;
import org.graylog.plugins.pipelineprocessor.ast.functions.Function;

import java.util.Collections;
import java.util.Set;

public class ThreatIntelPluginModule extends PluginModule {

    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
        // AlienVault OTX threat intel lookup.
        addMessageProcessorFunction(OTXDomainLookupFunction.NAME, OTXDomainLookupFunction.class);
        addMessageProcessorFunction(OTXIPLookupFunction.NAME, OTXIPLookupFunction.class);

        // Tor exit node lookup.
        addMessageProcessorFunction(TorExitNodeLookupFunction.NAME, TorExitNodeLookupFunction.class);

        // Spamhaus DROP and EDROP lookup.
        addMessageProcessorFunction(SpamhausIpLookupFunction.NAME, SpamhausIpLookupFunction.class);

        // abuse.ch Ransomeware
        addMessageProcessorFunction(AbuseChRansomDomainLookupFunction.NAME, AbuseChRansomDomainLookupFunction.class);

        // Private network lookup.
        addMessageProcessorFunction(PrivateNetLookupFunction.NAME, PrivateNetLookupFunction.class);
    }

    protected void addMessageProcessorFunction(String name, Class<? extends Function<?>> functionClass) {
        addMessageProcessorFunction(binder(), name, functionClass);
    }

    public static MapBinder<String, Function<?>> processorFunctionBinder(Binder binder) {
        return MapBinder.newMapBinder(binder, TypeLiteral.get(String.class), new TypeLiteral<Function<?>>() {});
    }

    public static void addMessageProcessorFunction(Binder binder, String name, Class<? extends Function<?>> functionClass) {
        processorFunctionBinder(binder).addBinding(name).to(functionClass);

    }

}
