package org.graylog.plugins.threatintel;

import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import org.graylog2.cluster.ClusterConfigChangedEvent;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.shared.utilities.AutoValueUtils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Provides up to date access to this plugins' cluster config without forcing consumers to listen to updates manually.
 */
@Singleton
public class PluginConfigService {

    private final ClusterConfigService clusterConfigService;
    private AtomicReference<ConfigVersions<ThreatIntelPluginConfiguration>> config = new AtomicReference<>();

    @Inject
    public PluginConfigService(final ClusterConfigService clusterConfigService, final EventBus serverEventBus) {
        this.clusterConfigService = clusterConfigService;
        final ThreatIntelPluginConfiguration currentVersion = clusterConfigService.get(ThreatIntelPluginConfiguration.class);
        final ConfigVersions<ThreatIntelPluginConfiguration> versions = ConfigVersions.of(null,
                Optional.ofNullable(currentVersion).orElse(ThreatIntelPluginConfiguration.defaults()));
        config.set(versions);
        serverEventBus.register(this);
    }

    public ConfigVersions<ThreatIntelPluginConfiguration> config() {
        return config.get();
    }

    @Subscribe
    public void handleUpdatedClusterConfig(ClusterConfigChangedEvent clusterConfigChangedEvent) {
        if (clusterConfigChangedEvent.type().equals(AutoValueUtils.getCanonicalName((ThreatIntelPluginConfiguration.class)))) {
            final ThreatIntelPluginConfiguration currentVersion = Optional.ofNullable(clusterConfigService.get(ThreatIntelPluginConfiguration.class))
                    .orElse(ThreatIntelPluginConfiguration.defaults());
            final ThreatIntelPluginConfiguration previous = config.get().getCurrent();
            config.set(ConfigVersions.of(previous, currentVersion));
        }
    }

    /**
     * Used by {@link PluginConfigService} to return the previously observed and current configuration
     * so that clients can act on changes if they need to.
     * @param <T> the plugin cluster configuration class
     */
    public static class ConfigVersions<T> {

        @Nullable
        private final T previous;

        @Nonnull
        private final T current;

        public ConfigVersions(@Nullable T previous, @Nonnull T current) {
            this.previous = previous;
            this.current = current;
        }

        public static <T> ConfigVersions<T> of(@Nullable T previous, @Nonnull T current) {
            return new ConfigVersions<>(previous, current);
        }

        public Optional<T> getPrevious() {
            return Optional.ofNullable(previous);
        }

        @Nonnull
        public T getCurrent() {
            return current;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ConfigVersions<?> that = (ConfigVersions<?>) o;
            return Objects.equals(previous, that.previous) &&
                    Objects.equals(current, that.current);
        }

        @Override
        public int hashCode() {
            return Objects.hash(previous, current);
        }
    }
}
