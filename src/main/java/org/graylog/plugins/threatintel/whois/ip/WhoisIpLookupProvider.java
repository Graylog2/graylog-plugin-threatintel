package org.graylog.plugins.threatintel.whois.ip;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.graylog.plugins.threatintel.tools.PrivateNet;
import org.graylog.plugins.threatintel.whois.cache.WhoisCacheService;
import org.graylog.plugins.threatintel.whois.cache.mongodb.WhoisDao;
import org.graylog2.database.NotFoundException;
import org.joda.time.DateTime;
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
    protected WhoisCacheService whoisCacheService;

    private boolean initialized = false;

    protected Meter lookupCount;
    protected Meter validLookupCount;
    protected Meter arinRequestCount;
    protected Timer arinRequestTiming;
    protected Meter databaseCacheHits;
    protected Timer databaseCacheLookupTiming;

    public void initialize(MetricRegistry metrics, WhoisCacheService whoisCacheService) {
        if (initialized) {
            return;
        }

        this.whoisCacheService = whoisCacheService;

        // Metrics
        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.validLookupCount = metrics.meter(name(this.getClass(), "validLookupCount"));
        this.arinRequestCount = metrics.meter(name(this.getClass(), "arinRequestCount"));
        this.arinRequestTiming = metrics.timer(name(this.getClass(), "arinRequestTiming"));
        this.databaseCacheHits = metrics.meter(name(this.getClass(), "dbCacheHits"));
        this.databaseCacheLookupTiming = metrics.timer(name(this.getClass(), "dbCacheLookupTime"));

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
                .expireAfterWrite(4, TimeUnit.HOURS)
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached IP WHOIS information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, WhoisIpLookupResult>() {
                    public WhoisIpLookupResult load(String ip) throws ExecutionException {
                        LOG.debug("WHOIS IP cache MISS: [{}]", ip);

                        // The value was not cached. Now try to find it in MongoDB.
                        Timer.Context time = databaseCacheLookupTiming.time();
                        try {
                            WhoisDao dao = whoisCacheService.findByIPAddress(ip);

                            databaseCacheHits.mark();
                            return new WhoisIpLookupResult(dao.organization(), dao.countryCode());
                        } catch (NotFoundException e) {
                            // Not found. Move on to actual WHOIS lookup below.
                        } finally {
                            time.stop();
                        }

                        // Not in cache, not in MongoDB. Look up WHOIS information and store in MongoDB.
                        try {
                            WhoisIpLookupResult result = loadWhois(ip);

                            // Store in MongoDB. (TTL takes care of eviction)
                            whoisCacheService.save(
                                    WhoisDao.create(null, ip, result.getOrganization(), result.getCountryCode(), DateTime.now().toDate())
                            );

                            return result;
                        }catch(Exception e) {
                            throw new ExecutionException(e);
                        }
                    }
                });

        initialized = true;
    }

    private WhoisIpLookupResult loadWhois(String ip) {
        arinRequestCount.mark();

        WhoisIpLookup lookup = new WhoisIpLookup();
        WhoisIpLookupResult result;

        Timer.Context time = arinRequestTiming.time();
        try {
            result = lookup.run(ip);
        } catch(Exception e) {
            LOG.error("Could not run WHOIS lookup for IP [{}]", ip);
            result = WhoisIpLookupResult.EMPTY;
        } finally {
            time.stop();
        }

        return result;
    }

    public WhoisIpLookupResult lookup(String ip) throws ExecutionException {
        lookupCount.mark();

        if (ip == null || ip.isEmpty()) {
            LOG.debug("NULL or empty ip passed to WHOIS lookup.");
            return null;
        }

        ip = ip.trim();

        if(PrivateNet.isInPrivateAddressSpace(ip)) {
            LOG.debug("IP [{}] is in private net as defined in RFC1918. Skipping.", ip);
            return null;
        }

        validLookupCount.mark();

        return cache.get(ip);
    }

    public boolean isInitialized() {
        return initialized;
    }

}
