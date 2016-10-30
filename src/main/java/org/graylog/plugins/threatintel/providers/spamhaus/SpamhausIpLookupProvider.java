package org.graylog.plugins.threatintel.providers.spamhaus;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.net.util.SubnetUtils;
import org.graylog.plugins.threatintel.providers.ConfiguredProvider;
import org.graylog.plugins.threatintel.providers.GenericLookupResult;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;

// TODO extract a lot of stuff here to a shared class with TorExitNodeLookupProvider
public class SpamhausIpLookupProvider extends ConfiguredProvider {

    private static final Logger LOG = LoggerFactory.getLogger(SpamhausIpLookupProvider.class);

    private static SpamhausIpLookupProvider INSTANCE = new SpamhausIpLookupProvider();

    public static SpamhausIpLookupProvider getInstance() {
        return INSTANCE;
    }

    protected final LoadingCache<String, GenericLookupResult> cache;

    private static final String[] lists = {
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/edrop.txt"
    };

    private ImmutableList<SubnetUtils.SubnetInfo> subnets;

    protected boolean initialized = false;

    protected Meter lookupCount;
    protected Timer refreshTiming;
    protected Timer lookupTiming;

    private SpamhausIpLookupProvider() {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES) // TODO make configurable. also add maximum # of entries
                .removalListener(removalNotification -> {
                    LOG.trace("Invalidating cached threat intel information for key [{}].", removalNotification.getKey());
                })
                .build(new CacheLoader<String, GenericLookupResult>() {
                    public GenericLookupResult load(String key) throws ExecutionException {
                        LOG.debug("Spamhaus threat intel cache MISS: [{}]", key);

                        try {
                            return loadIntel(key);
                        }catch(Exception e) {
                            throw new ExecutionException(e);
                        }
                    }
                });


        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("threatintel-spamhaus-refresher-%d")
                        .build()
        );

        // Automatically refresh local block list table.
        executor.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                try {
                    refreshTable();
                } catch (Exception e) {
                    LOG.error("Could not refresh local Spamhaus drop list table.", e);
                }
            }
        }, 5, 5, TimeUnit.MINUTES); // First refresh happens in initialize(). #racyRaceConditions
    }

    public void initialize(final ClusterConfigService clusterConfigService,
                           final MetricRegistry metrics) {
        if(initialized) {
            return;
        }

        // Set up config refresher and initial load.
        initializeConfigRefresh(clusterConfigService);

        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.refreshTiming = metrics.timer(name(this.getClass(), "refreshTime"));
        this.lookupTiming = metrics.timer(name(this.getClass(), "lookupTime"));

        // Initially load table. Doing this here because we need this blocking.
        try {
            refreshTable();
        } catch (IOException | ExecutionException e) {
            LOG.error("Could not refresh Spamhaus drop list table.", e);
        }

        this.initialized = true;
    }

    public GenericLookupResult lookup(String ip) throws Exception {
        if(!initialized) {
            throw new IllegalAccessException("Provider is not initialized.");
        }

        // See if we are supposed to run at all.
        if(this.config == null || !this.config.spamhausEnabled()) {
            LOG.warn("Spamhaus IP lookup requested but not enabled in configuration. Please enable it first.");
            return null;
        }

        LOG.debug("Loading Spamhaus intel for IP [{}].", ip);

        if(ip == null || ip.isEmpty()) {
            LOG.debug("IP string for Spamhaus intel is empty.");
            return GenericLookupResult.FALSE;
        }

        return cache.get(ip);
    }

    private GenericLookupResult loadIntel(String ip) throws Exception {
        if(ip == null) {
            throw new ExecutionException("IP is NULL", new IllegalAccessException());
        }

        Timer.Context timer = this.lookupTiming.time();
        for (SubnetUtils.SubnetInfo subnet : subnets) {
            if(subnet.isInRange(ip)) {
                return GenericLookupResult.TRUE;
            }
        }
        timer.stop();

        return GenericLookupResult.FALSE;
    }

    public void refreshTable() throws IOException, ExecutionException {
        LOG.info("Refreshing internal table of Spamhaus drop list IPs.");
        ImmutableList.Builder<SubnetUtils.SubnetInfo> list = new ImmutableList.Builder<>();

        // TODO make timeouts configurable
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        for (String url : lists) {
            Response response = null;

            Call request = client.newCall(new Request.Builder()
                    .get()
                    .url(url)
                    .header("User-Agent", "graylog-server (threatintel-plugin)")
                    .build());

            try {
                Timer.Context timer = this.refreshTiming.time();
                response = request.execute();
                timer.stop();

                if(response.code() != 200) {
                    throw new ExecutionException("Expected Spamhaus to respond with HTTP status 200 but got [" + response.code() + "].", null);
                }

                // Read response line by line.
                Scanner scanner = new Scanner(response.body().byteStream());
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();

                    if (!line.isEmpty() && !line.startsWith(";") && line.contains(";")) {
                        String[] parts = line.split(";");

                        SubnetUtils su = new SubnetUtils(parts[0].trim());
                        list.add(su.getInfo());
                    }
                }
                scanner.close();
            } finally {
                if(response != null) {
                    response.close();
                }
            }
        }

        // Le overwrite.
        this.subnets = list.build();
    }

}
