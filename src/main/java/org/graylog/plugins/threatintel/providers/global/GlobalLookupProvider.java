package org.graylog.plugins.threatintel.providers.global;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.graylog.plugins.threatintel.providers.ConfiguredProvider;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog.plugins.threatintel.providers.GlobalIncludedProvider;
import org.graylog.plugins.threatintel.providers.abusech.AbuseChRansomLookupProvider;
import org.graylog.plugins.threatintel.providers.spamhaus.SpamhausIpLookupProvider;
import org.graylog.plugins.threatintel.providers.tor.TorExitNodeLookupProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import static com.codahale.metrics.MetricRegistry.name;

public class GlobalLookupProvider extends ConfiguredProvider {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalLookupProvider.class);


    // This is a little clumsy and could probably be solved nicer and more automatic. Maybe using annotations.
    private static final ImmutableList<Class<? extends GlobalIncludedProvider>> DOMAIN_PROVIDERS = new ImmutableList.Builder<Class<? extends GlobalIncludedProvider>>()
            .add(AbuseChRansomLookupProvider.class)
            .build();

    private static final ImmutableList<Class<? extends GlobalIncludedProvider>> IP_PROVIDERS = new ImmutableList.Builder<Class<? extends GlobalIncludedProvider>>()
            .add(TorExitNodeLookupProvider.class)
            .add(AbuseChRansomLookupProvider.class)
            .add(SpamhausIpLookupProvider.class)
            .build();

    private boolean initialized = false;

    protected Meter lookupCount;
    protected Timer lookupTiming;

    private static GlobalLookupProvider INSTANCE = new GlobalLookupProvider();

    public static GlobalLookupProvider getInstance() {
        return INSTANCE;
    }

    public void initialize(final MetricRegistry metrics) {
        if(initialized) {
            return;
        }

        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.lookupTiming = metrics.timer(name(this.getClass(), "lookupTime"));

        this.initialized = true;
    }

    public GlobalLookupResult lookupIp(String ip, String prefix) {
        return lookup(ip, prefix, IP_PROVIDERS);
    }

    public GlobalLookupResult lookupDomain(String domain, String prefix) {
        return lookup(domain, prefix, DOMAIN_PROVIDERS);
    }

    private GlobalLookupResult lookup(String key, String prefix, List<Class<? extends GlobalIncludedProvider>> providers) {
        this.lookupCount.mark();

        Timer.Context time = this.lookupTiming.time();

        List<String> matches = Lists.newArrayList();
        for (Class<? extends GlobalIncludedProvider> clazz : providers) {
            try {
                Method getInstance = clazz.getMethod("getInstance");
                GlobalIncludedProvider provider = (GlobalIncludedProvider) getInstance.invoke(null);

                LOG.debug("Running [{}] threat intelligence lookup as part of global lookup.", provider.getIdentifier());

                // Run provider.
                GenericLookupResult intel;
                try {
                    intel = provider.lookup(key, true);
                } catch (Exception e) {
                    throw new RuntimeException("Could not fetch intel from [" + clazz.getCanonicalName() + "] as part of global lookup.", e);
                }
                if (intel != null && intel.isMatch()) { // intel can be null in case of error or deactivated provider.
                    matches.add(provider.getIdentifier());
                }
            } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
                throw new RuntimeException("Could not instantiate provider object on [" + clazz.getCanonicalName() + "]. Is getInstance() implemented?", e);
            }
        }

        time.stop();

        return GlobalLookupResult.fromMatches(matches, prefix);
    }

}
