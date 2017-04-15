package org.graylog.plugins.threatintel.providers.reversedns;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;

public class ReverseDNSLookupProvider {

    protected static final Logger LOG = LoggerFactory.getLogger(ReverseDNSLookupProvider.class);

    public static final String NAME = "Reverse DNS lookup";

    private final ObjectMapper om;

    protected LoadingCache<String, String> cache;
    protected Meter lookupCount;
    protected Timer lookupTiming;

    private boolean initialized = false;

    private static final ReverseDNSLookupProvider INSTANCE = new ReverseDNSLookupProvider();

    public static ReverseDNSLookupProvider getInstance() {
        return INSTANCE;
    }

    private ReverseDNSLookupProvider() {
        // TODO inject
        this.om = new ObjectMapper();
        this.om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.om.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);

        this.cache = CacheBuilder.newBuilder()
                .recordStats()
                .expireAfterWrite(60, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached [{}] information for key [{}].", NAME, removalNotification.getKey());
                })
                .build(new CacheLoader<String, String>() {
                    @Override
                    public String load(String key) throws ExecutionException {
                        LOG.debug("{} cache MISS: [{}]", NAME, key);

                        try {
                            return fetch(key);
                        }catch(Exception e) {
                            throw new ExecutionException(e);
                        }
                    }
                });
    }

    public void initialize(final MetricRegistry metrics) {
        if(initialized) {
            return;
        }

        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.lookupTiming = metrics.timer(name(this.getClass(), "lookupTime"));
        metrics.register(name(this.getClass(), "cacheSize"), new Gauge<Long>() {
            @Override
            public Long getValue() {
                return cache.size();
            }
        });
        metrics.register(name(this.getClass(), "cacheHitCount"), new Gauge<Long>() {
            @Override
            public Long getValue() {
                return cache.stats().hitCount();
            }
        });
        metrics.register(name(this.getClass(), "cacheMissCount"), new Gauge<Long>() {
            @Override
            public Long getValue() {
                return cache.stats().missCount();
            }
        });
        metrics.register(name(this.getClass(), "cacheExceptionCount"), new Gauge<Long>() {
            @Override
            public Long getValue() {
                return cache.stats().loadExceptionCount();
            }
        });

        initialized = true;
    }

    private String fetch(String key) throws Exception {
        String result;

        Timer.Context timer = this.lookupTiming.time();
        result = InetAddress.getByName(key).getCanonicalHostName();
        timer.stop();

        return result;
    }

    public String lookup(String ip) throws ExecutionException {
        if (ip == null || ip.isEmpty()) {
            LOG.debug("Empty parameter provided for {} reverse DNS lookup.", NAME);
            return null;
        }

        lookupCount.mark();

        return cache.get(ip);
    }

}
