package org.graylog.plugins.threatintel.whois.ip;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.graylog.plugins.threatintel.tools.PrivateNet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;

public class WhoisIpLookupProvider {

    private static final Logger LOG = LoggerFactory.getLogger(WhoisIpLookupProvider.class);

    private static WhoisIpLookupProvider INSTANCE = new WhoisIpLookupProvider();

    public static WhoisIpLookupProvider getInstance() {
        return INSTANCE;
    }

    protected LoadingCache<String, WhoisIpLookupResult> cache;

    private boolean initialized = false;

    protected Meter lookupCount;
    protected Timer lookupTiming;

    public void initialize(MetricRegistry metrics) {
        if (initialized) {
            return;
        }

        // Metrics
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


        this.cache = CacheBuilder.newBuilder()
                .recordStats()
                .expireAfterWrite(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached IP WHOIS information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, WhoisIpLookupResult>() {
                    public WhoisIpLookupResult load(String ip) throws ExecutionException {
                        LOG.debug("WHOIS IP cache MISS: [{}]", ip);

                        try {
                            return loadWhois(ip);
                        }catch(Exception e) {
                            throw new ExecutionException(e);
                        }
                    }
                });

        initialized = true;
    }

    private WhoisIpLookupResult loadWhois(String ip) {
        WhoisIpLookup lookup = new WhoisIpLookup();

        Timer.Context time = lookupTiming.time();
        WhoisIpLookupResult result = lookup.run(ip);
        time.stop();

        return result;
    }

    public WhoisIpLookupResult lookup(String ip) throws ExecutionException {
        if (ip == null || ip.isEmpty()) {
            LOG.debug("NULL or empty ip passed to WHOIS lookup.");
            return null;
        }

        ip = ip.trim();

        if(PrivateNet.isInPrivateAddressSpace(ip)) {
            LOG.debug("IP [{}] is in private net as defined in RFC1918. Skipping.", ip);
            return null;
        }

        lookupCount.mark();

        return cache.get(ip);
    }

}
