package org.graylog.plugins.threatintel.whois.ip;

import autovalue.shaded.com.google.common.common.collect.Maps;
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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;

public class WhoisIpLookupProvider {

    private static final Logger LOG = LoggerFactory.getLogger(WhoisIpLookupProvider.class);

    private static WhoisIpLookupProvider INSTANCE = new WhoisIpLookupProvider();

    public static WhoisIpLookupProvider getInstance() {
        return INSTANCE;
    }

    protected LoadingCache<String, Map<String, Object>> cache;

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
                .expireAfterWrite(12, TimeUnit.HOURS) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached IP WHOIS information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, Map<String, Object>>() {
                    public Map<String, Object> load(String ip) throws ExecutionException {
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

    private Map<String, Object> loadWhois(String ip) {
        WhoisIpLookup lookup = new WhoisIpLookup();

        Map<String, Object> result;
        Timer.Context time = lookupTiming.time();
        try {
             result = lookup.run(ip);

            if(result == null) {
                result = new HashMap<String, Object>(){{
                    put("whois_empty_result", true);
                }};
            }
        } catch (Exception e) {
            result = new HashMap<String, Object>(){{
                put("whois_error", e.getMessage());
            }};
        } finally {
            time.stop();
        }

        return result;
    }

    public WhoisIpLookupResult lookup(String ip, String prefix) throws ExecutionException {
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


        Map<String, Object> whois = cache.get(ip);

        // Prefix fields. Doing that here to not cache individually per prefix. #computering
        Map<String, Object> resultMap = Maps.newHashMap();
        for (Map.Entry<String, Object> field : whois.entrySet()) {
            resultMap.put(prefix + "_" + field.getKey(), field.getValue());
        }

        return new WhoisIpLookupResult(resultMap);
    }

}
