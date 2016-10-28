package org.graylog.plugins.threatintel.providers.tor;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
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

public class TorExitNodeLookupProvider {

    private static final Logger LOG = LoggerFactory.getLogger(TorExitNodeLookupProvider.class);

    private static TorExitNodeLookupProvider INSTANCE = new TorExitNodeLookupProvider();

    public static TorExitNodeLookupProvider getInstance() {
        return INSTANCE;
    }

    private ImmutableList<String> exitNodes;

    protected boolean initialized = false;

    protected Meter lookupCount;
    protected Timer refreshTiming;

    private TorExitNodeLookupProvider() {
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("threatintel-tor-exit-nodes-refresher-%d")
                        .build()
        );

        // Automatically refresh local table of exit nodes.
        executor.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                try {
                    refreshTable();
                } catch (Exception e) {
                    LOG.error("Could not refresh list of Tor exit nodes.", e);
                }
            }
        }, 5, 5, TimeUnit.MINUTES); // First refresh happens in initialize(). #racyRaceConditions
    }

    public void initialize(final ClusterConfigService clusterConfigService,
                           final MetricRegistry metrics) {
        if(initialized) {
            return;
        }

        this.lookupCount = metrics.meter(name(this.getClass(), "lookupCount"));
        this.refreshTiming = metrics.timer(name(this.getClass(), "refreshTime"));

        // Initially load exit node table. Doing this here because we need this blocking.
        try {
            refreshTable();
        } catch (IOException | ExecutionException e) {
            LOG.error("Could not refresh list of Tor exit nodes.", e);
        }

        this.initialized = true;
    }

    public TorExitNodeLookupResult lookup(String ip) throws Exception {
        if(!initialized) {
            throw new IllegalAccessException("Provider is not initialized.");
        }

        LOG.debug("Loading Tor exit node intel for IP [{}].", ip);

        if(ip == null) {
            throw new ExecutionException("IP is NULL", new IllegalAccessException());
        }

        if(exitNodes.contains(ip.trim())) {
            return TorExitNodeLookupResult.TRUE;
        } else {
            return TorExitNodeLookupResult.FALSE;
        }
    }

    public void refreshTable() throws IOException, ExecutionException {
        LOG.info("Refreshing internal table of known Tor exit nodes.");
        Response response = null;

        // TODO make timeouts configurable
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .followSslRedirects(true)
                .build();

        Call request = client.newCall(new Request.Builder()
                .get()
                .url(new HttpUrl.Builder()
                        .host("check.torproject.org")
                        .scheme("https")
                        .addPathSegment("exit-addresses")
                        .build())
                .header("User-Agent", "graylog-server (threatintel-plugin)")
                .build());

        try {
            Timer.Context timer = this.refreshTiming.time();
            response = request.execute();
            timer.stop();

            if(response.code() != 200) {
                throw new ExecutionException("Expected Tor exit node list responding with HTTP status 200 but got [" + response.code() + "].", null);
            }

            ImmutableList.Builder<String> list = new ImmutableList.Builder<>();

            // Read response line by line.
            Scanner scanner = new Scanner(response.body().byteStream());
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();

                if (line.startsWith("ExitAddress")) {
                    String[] parts = line.split(" ");
                    if(parts.length != 4) {
                        LOG.warn("Malformed tor exit node entry: {}", line);
                    } else {
                        String ip = parts[1];

                        LOG.debug("Adding tor exit node: {}", ip);
                        list.add(ip);
                    }
                }
            }
            scanner.close();

            // Le overwrite.
            this.exitNodes = list.build();
        } finally {
            if(response != null) {
                response.close();
            }
        }
    }

}
