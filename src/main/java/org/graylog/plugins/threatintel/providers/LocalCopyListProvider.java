package org.graylog.plugins.threatintel.providers;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;

public abstract class LocalCopyListProvider<T> extends ConfiguredProvider {

    protected LoadingCache<String, T> cache;

    protected static final Logger LOG = LoggerFactory.getLogger(LocalCopyListProvider.class);

    protected boolean initialized = false;
    protected final String sourceName;

    protected Meter lookupCount;
    protected Timer refreshTiming;
    protected Timer lookupTiming;

    protected LocalCopyListProvider(String sourceName) {
        this.sourceName = sourceName;
    }

    public void initialize(final ClusterConfigService clusterConfigService,
                              final MetricRegistry metrics) {
        if(initialized) {
            return;
        }

        // Metrics
        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.refreshTiming = metrics.timer(name(this.getClass(), "refreshTime"));
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

        // Periodical configuration refresh.
        initializeConfigRefresh(clusterConfigService);

        this.cache = CacheBuilder.newBuilder()
                .recordStats()
                .expireAfterWrite(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached [{}] information for key [{}].", sourceName, removalNotification.getKey());
                })
                .build(new CacheLoader<String, T>() {
                    public T load(String key) throws ExecutionException {
                        LOG.debug("{} cache MISS: [{}]", sourceName, key);

                        try {
                            return fetchIntel(key);
                        }catch(Exception e) {
                            throw new ExecutionException(e);
                        }
                    }
                });

        // Source table refresh.
        ScheduledExecutorService sourceTableRefreshExecutor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("threatintel-" + sourceName + "-refresher-%d")
                        .build()
        );

        // Automatically refresh local block list table.
        sourceTableRefreshExecutor.scheduleWithFixedDelay((Runnable) () -> {
            try {
                refreshTable();
            } catch (Exception e) {
                LOG.error("Could not refresh [{}] table.", sourceName, e);
            }
        }, 5, 5, TimeUnit.MINUTES); // First refresh happens below. #racyRaceConditions

        // Initially load table. Doing this here because we need this blocking.
        try {
            refreshTable();
        } catch (ExecutionException e) {
            LOG.error("Could not refresh [{}] source table.", sourceName, e);
        }

        this.initialized = true;
    }

    public T lookup(String key) throws Exception {
        if(!initialized) {
            throw new IllegalAccessException("Provider is not initialized.");
        }

        if (key == null || key.isEmpty()) {
            LOG.debug("Empty parameter provided for {} threat intel lookup.", sourceName);
            return null;
        }

        if(!isEnabled()) {
            LOG.error("{} threat intel lookup requested but not enabled in configuration. Please enable it first in the web interface at System -> Configurations.", sourceName);
            return null;
        }

        lookupCount.mark();

        return cache.get(key);
    }


    protected abstract boolean isEnabled();

    protected abstract T fetchIntel(String key) throws Exception;

    protected abstract void refreshTable() throws ExecutionException;

}
