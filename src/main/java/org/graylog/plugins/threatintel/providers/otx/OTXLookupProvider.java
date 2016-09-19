package org.graylog.plugins.threatintel.providers.otx;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public abstract class OTXLookupProvider {

    protected static final Logger LOG = LoggerFactory.getLogger(OTXLookupProvider.class);

    protected final LoadingCache<String, OTXIntel> cache;
    protected final ObjectMapper om;

    protected OTXLookupProvider() {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached threat intel information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, OTXIntel>() {
                    public OTXIntel load(String key) throws ExecutionException {
                        LOG.trace("OTX threat intel cache MISS: [{}]", key);
                        return loadIntel(key);
                    }
                });

        // TODO it should be possible to get this injected.
        this.om = new ObjectMapper();
        om.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
        om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    protected abstract OTXIntel loadIntel(String key) throws ExecutionException;

}
