package org.graylog.plugins.threatintel.providers.otx;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class OTXDomainLookupProvider {

    private static final Logger LOG = LoggerFactory.getLogger(OTXDomainLookupProvider.class);

    private static OTXDomainLookupProvider INSTANCE = new OTXDomainLookupProvider();

    public static OTXDomainLookupProvider getInstance() {
        return INSTANCE;
    }

    private final LoadingCache<String, OTXIntel> cache;

    // TODO we'll probably move this out into a bunch of generics and an interface when the second provider comes around
    private OTXDomainLookupProvider() {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterAccess(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached threat intel information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, OTXIntel>() {
                    public OTXIntel load(String domain) {
                        LOG.trace("Threat intel cache MISS: [{}]", domain);
                        return loadIntel(domain);
                    }
                });
    }

    public OTXIntel lookup(String domain) throws ExecutionException {
        return this.cache.get(domain);
    }

    private OTXIntel loadIntel(String domain) {
        LOG.debug("Loading OTX threat intel for domain [{}].", domain);

        // TODO implement calls to threat intelligence database.

        OTXIntel intel = new OTXIntel();
        intel.addPulse(new OTXPulse("56aaacfa67db8c6aaee02764", "A Peek Behind the Cryptowall"));
        intel.addPulse(new OTXPulse("57d8a4fdaa954c387e689a27", "LuaBot: Malware targeting cable modems"));
        return intel;
    }


}
