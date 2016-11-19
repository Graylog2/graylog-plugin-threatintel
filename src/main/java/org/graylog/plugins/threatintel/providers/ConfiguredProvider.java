package org.graylog.plugins.threatintel.providers;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ConfiguredProvider  {

    protected static final Logger LOG = LoggerFactory.getLogger(ConfiguredProvider.class);

    protected ThreatIntelPluginConfiguration config;

    protected void initializeConfigRefresh(final ClusterConfigService clusterConfigService) {
        // Configuration refresh.
        Runnable refresh = () -> {
            try {
                this.config = clusterConfigService.get(ThreatIntelPluginConfiguration.class);
            } catch (Exception e) {
                LOG.error("Could not refresh threat intel plugin configuration.", e);
            }
        };

        ScheduledExecutorService configurationRefreshExecutor = Executors.newSingleThreadScheduledExecutor(
                new ThreadFactoryBuilder()
                        .setDaemon(true)
                        .setNameFormat("threatintel-configuration-refresher-%d")
                        .build()
        );

        configurationRefreshExecutor.scheduleWithFixedDelay(refresh, 0, 15, TimeUnit.SECONDS);
    }

    public ThreatIntelPluginConfiguration getConfig() {
        return config;
    }

}
