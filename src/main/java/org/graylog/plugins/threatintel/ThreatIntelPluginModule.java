package org.graylog.plugins.threatintel;

import com.google.inject.Binder;
import com.google.inject.Scopes;
import com.google.inject.TypeLiteral;
import com.google.inject.multibindings.MapBinder;
import org.graylog.plugins.pipelineprocessor.ast.functions.Function;
import org.graylog.plugins.threatintel.migrations.V20170815111700_CreateThreatIntelLookupTables;
import org.graylog.plugins.threatintel.misc.functions.LookupTableFunction;
import org.graylog.plugins.threatintel.misc.functions.PrivateNetLookupFunction;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog.plugins.threatintel.providers.abusech.domain.AbuseChRansomDomainLookupFunction;
import org.graylog.plugins.threatintel.providers.abusech.ip.AbuseChRansomIpLookupFunction;
import org.graylog.plugins.threatintel.providers.global.domain.GlobalDomainLookupFunction;
import org.graylog.plugins.threatintel.providers.global.ip.GlobalIpLookupFunction;
import org.graylog.plugins.threatintel.providers.otx.domain.OTXDomainLookupFunction;
import org.graylog.plugins.threatintel.providers.otx.ip.OTXIPLookupFunction;
import org.graylog.plugins.threatintel.providers.spamhaus.SpamhausEDROPDataAdapter;
import org.graylog.plugins.threatintel.providers.spamhaus.SpamhausIpLookupFunction;
import org.graylog.plugins.threatintel.providers.tor.TorExitNodeDataAdapter;
import org.graylog.plugins.threatintel.providers.tor.TorExitNodeLookupFunction;
import org.graylog.plugins.threatintel.whois.cache.WhoisCacheService;
import org.graylog.plugins.threatintel.whois.cache.mongodb.MongoDBWhoisCacheService;
import org.graylog.plugins.threatintel.whois.ip.WhoisDataAdapter;
import org.graylog.plugins.threatintel.whois.ip.WhoisLookupIpFunction;
import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

import java.util.Collections;
import java.util.Set;

public class ThreatIntelPluginModule extends PluginModule {

    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
        // Setup DI.
        bind(WhoisCacheService.class).to(MongoDBWhoisCacheService.class).in(Scopes.SINGLETON);

        // AlienVault OTX threat intel lookup.
        addMessageProcessorFunction(OTXDomainLookupFunction.NAME, OTXDomainLookupFunction.class);
        addMessageProcessorFunction(OTXIPLookupFunction.NAME, OTXIPLookupFunction.class);

        // Tor exit node lookup.
        addMessageProcessorFunction(TorExitNodeLookupFunction.NAME, TorExitNodeLookupFunction.class);

        // Spamhaus DROP and EDROP lookup.
        addMessageProcessorFunction(SpamhausIpLookupFunction.NAME, SpamhausIpLookupFunction.class);

        // abuse.ch Ransomware
        addMessageProcessorFunction(AbuseChRansomDomainLookupFunction.NAME, AbuseChRansomDomainLookupFunction.class);
        addMessageProcessorFunction(AbuseChRansomIpLookupFunction.NAME, AbuseChRansomIpLookupFunction.class);

        // Global/combined lookup
        addMessageProcessorFunction(GlobalIpLookupFunction.NAME, GlobalIpLookupFunction.class);
        addMessageProcessorFunction(GlobalDomainLookupFunction.NAME, GlobalDomainLookupFunction.class);

        // WHOIS IP lookup.
        addMessageProcessorFunction(WhoisLookupIpFunction.NAME, WhoisLookupIpFunction.class);

        // Private network lookup.
        addMessageProcessorFunction(PrivateNetLookupFunction.NAME, PrivateNetLookupFunction.class);

        installLookupDataAdapter(SpamhausEDROPDataAdapter.NAME, SpamhausEDROPDataAdapter.class, SpamhausEDROPDataAdapter.Factory.class, SpamhausEDROPDataAdapter.Config.class);
        installLookupDataAdapter(TorExitNodeDataAdapter.NAME, TorExitNodeDataAdapter.class, TorExitNodeDataAdapter.Factory.class, TorExitNodeDataAdapter.Config.class);
        installLookupDataAdapter(WhoisDataAdapter.NAME, WhoisDataAdapter.class, WhoisDataAdapter.Factory.class, WhoisDataAdapter.Config.class);

        addMigration(V20170815111700_CreateThreatIntelLookupTables.class);

        addDomainFunction("abusech_ransomware", AbuseChRansomDomainLookupFunction.class);
        addIPFunction("abusech_ransomware", AbuseChRansomIpLookupFunction.class);
        addIPFunction("spamhaus", SpamhausIpLookupFunction.class);
        addIPFunction("tor", TorExitNodeLookupFunction.class);
    }

    private void addMessageProcessorFunction(String name, Class<? extends Function<?>> functionClass) {
        addMessageProcessorFunction(binder(), name, functionClass);
    }

    private MapBinder<String, Function<?>> processorFunctionBinder(Binder binder) {
        return MapBinder.newMapBinder(binder, TypeLiteral.get(String.class), new TypeLiteral<Function<?>>() {});
    }

    private void addMessageProcessorFunction(Binder binder, String name, Class<? extends Function<?>> functionClass) {
        processorFunctionBinder(binder).addBinding(name).to(functionClass);

    }

    private MapBinder<String, LookupTableFunction<? extends GenericLookupResult>> domainFunctionBinder() {
        return MapBinder.newMapBinder(binder(), TypeLiteral.get(String.class), new TypeLiteral<LookupTableFunction<? extends GenericLookupResult>>() {}, DomainFunctions.class);
    }

    private MapBinder<String, LookupTableFunction<? extends GenericLookupResult>> ipFunctionBinder() {
        return MapBinder.newMapBinder(binder(), TypeLiteral.get(String.class), new TypeLiteral<LookupTableFunction<? extends GenericLookupResult>>() {}, IPFunctions.class);
    }

    private void addDomainFunction(String id, Class<? extends LookupTableFunction<? extends GenericLookupResult>> functionClass) {
        domainFunctionBinder().addBinding(id).to(functionClass);
    }

    private void addIPFunction(String id, Class<? extends LookupTableFunction<? extends GenericLookupResult>> functionClass) {
        ipFunctionBinder().addBinding(id).to(functionClass);
    }
}
