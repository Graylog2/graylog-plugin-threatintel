package org.graylog.plugins.threatintel.migrations;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auto.value.AutoValue;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog2.bundles.BundleService;
import org.graylog2.bundles.ConfigurationBundle;
import org.graylog2.migrations.Migration;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.shared.users.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.net.URL;
import java.time.ZonedDateTime;

public class V20170815111700_CreateThreatIntelLookupTables extends Migration {
    private static final Logger LOG = LoggerFactory.getLogger(V20170815111700_CreateThreatIntelLookupTables.class);

    private final BundleService bundleService;
    private final ObjectMapper objectMapper;
    private final UserService userService;
    private final ClusterConfigService clusterConfigService;

    @Inject
    public V20170815111700_CreateThreatIntelLookupTables(final BundleService bundleService,
                                                         final ObjectMapper objectMapper,
                                                         final UserService userService,
                                                         final ClusterConfigService clusterConfigService) {
        this.bundleService = bundleService;
        this.objectMapper = objectMapper;
        this.userService = userService;
        this.clusterConfigService = clusterConfigService;
    }

    @Override
    public ZonedDateTime createdAt() {
        return ZonedDateTime.parse("2017-08-15T09:17:00Z");
    }

    @Override
    public void upgrade() {
        if (clusterConfigService.get(MigrationCompleted.class) != null) {
            LOG.debug("Migration already completed.");
            return;
        }

        try {
            final URL contentPackURL = V20170815111700_CreateThreatIntelLookupTables.class.getResource("V20170815111700_CreateThreatIntelLookupTables-content-pack.json");
            final ConfigurationBundle configurationBundle = this.objectMapper.readValue(contentPackURL, ConfigurationBundle.class);
            final ConfigurationBundle savedBundle = this.bundleService.insert(configurationBundle);
            this.bundleService.applyConfigurationBundle(savedBundle, this.userService.getAdminUser());
            clusterConfigService.write(MigrationCompleted.create(savedBundle.getId()));
        } catch (IOException e) {
            LOG.error("Unable to import content pack for threat intel plugin: ", e);
        }
    }

    @JsonAutoDetect
    @AutoValue
    @WithBeanGetter
    public static abstract class MigrationCompleted {
        @JsonProperty
        public abstract String contentBundleId();

        @JsonCreator
        public static MigrationCompleted create(final String contentBundleId) {
            return new AutoValue_V20170815111700_CreateThreatIntelLookupTables_MigrationCompleted(contentBundleId);
        }
    }
}
