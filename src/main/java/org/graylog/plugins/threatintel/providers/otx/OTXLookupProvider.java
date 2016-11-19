package org.graylog.plugins.threatintel.providers.otx;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Response;
import org.graylog.plugins.threatintel.providers.ConfiguredProvider;
import org.graylog.plugins.threatintel.providers.otx.json.OTXPulseResponse;
import org.graylog.plugins.threatintel.providers.otx.json.OTXResponse;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;

public abstract class OTXLookupProvider extends ConfiguredProvider {

    protected static final Logger LOG = LoggerFactory.getLogger(OTXLookupProvider.class);

    protected final LoadingCache<String, OTXLookupResult> cache;
    protected final ObjectMapper om;

    protected Meter lookupCount;
    protected Timer lookupTiming;

    protected boolean initialized = false;

    protected OTXLookupProvider() {
        this.cache = CacheBuilder.newBuilder()
                .recordStats()
                .expireAfterWrite(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached threat intel information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, OTXLookupResult>() {
                    public OTXLookupResult load(String key) throws ExecutionException {
                        LOG.debug("OTX threat intel cache MISS: [{}]", key);
                        OTXIntel intel = loadIntel(key);

                        if(intel == null) {
                            return OTXLookupResult.EMPTY;
                        }

                        return OTXLookupResult.buildFromIntel(intel);
                    }
                });

        // TODO it should be possible to get this injected.
        this.om = new ObjectMapper();
        om.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
        om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public void initialize(final ClusterConfigService clusterConfigService,
                           final MetricRegistry metrics) {
        if(initialized) {
            return;
        }

        // Set up config refresher and initial load.
        initializeConfigRefresh(clusterConfigService);

        // Metrics.
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

        this.initialized = true;
    }

    public OTXLookupResult lookup(String key) throws Exception {
        if(!initialized) {
            throw new IllegalAccessException("Provider is not initialized.");
        }

        // See if we are supposed to run at all.
        if(this.getConfig() == null || !this.getConfig().otxEnabled()) {
            LOG.warn("OTX domain lookup requested but OTX is not enabled in configuration. Please enable it first.");
            return null;
        }

        if(!this.getConfig().isOtxComplete()) {
            LOG.warn("OTX domain lookup requested but OTX is not fully configured. Please configure all required parameters.");
            return null;
        }

        this.lookupCount.mark();

        return this.cache.get(key);
    }

    protected OkHttpClient getHttpClient() {
        // TODO make timeouts configurable
        return new OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();
    }

    protected OTXIntel callOTX(Call request) throws ExecutionException {
        Response response = null;
        try {
            Timer.Context timer = this.lookupTiming.time();
            response = request.execute();
            timer.stop();

            if(response.code() == 400) {
                LOG.debug("Internal, reserved or invalid ip/domain/key looked up in OTX. Ignoring.");
                return null;
            }

            if(response.code() != 200) {
                throw new ExecutionException("Expected OTX threat intel API HTTP status 200 or 400 but got [" + response.code() + "].", null);
            }

            // Parse response.
            OTXIntel intel = new OTXIntel();
            OTXResponse otx = om.readValue(response.body().string(), OTXResponse.class);
            if (otx.pulseInfo != null && otx.pulseInfo.pulses != null) {
                for (OTXPulseResponse pulse : otx.pulseInfo.pulses) {
                    intel.addPulse(new OTXPulse(pulse.id, pulse.name));
                }
            } else {
                LOG.warn("Unexpected OTX threat intel lookup API response: {}", response.body().string().substring(0, 255));
            }

            return intel;
        } catch(IOException e) {
            throw new ExecutionException("Could not load OTX response.", e);
        } finally {
            if(response != null) {
                response.close();
            }
        }
    }

    protected abstract OTXIntel loadIntel(String key) throws ExecutionException;

}
