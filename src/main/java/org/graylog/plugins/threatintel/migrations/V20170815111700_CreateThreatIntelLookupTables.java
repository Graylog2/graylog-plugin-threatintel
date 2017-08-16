package org.graylog.plugins.threatintel.migrations;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.graylog2.bundles.BundleService;
import org.graylog2.bundles.ConfigurationBundle;
import org.graylog2.migrations.Migration;
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

    @Inject
    public V20170815111700_CreateThreatIntelLookupTables(BundleService bundleService, ObjectMapper objectMapper, UserService userService) {
        this.bundleService = bundleService;
        this.objectMapper = objectMapper;
        this.userService = userService;
    }

    @Override
    public ZonedDateTime createdAt() {
        return ZonedDateTime.parse("2017-08-15T09:17:00Z");
    }

    @Override
    public void upgrade() {
        try {
            final URL contentPackURL = V20170815111700_CreateThreatIntelLookupTables.class.getResource("V20170815111700_CreateThreatIntelLookupTables-content-pack.json");
            final ConfigurationBundle configurationBundle = this.objectMapper.readValue(contentPackURL, ConfigurationBundle.class);
            final ConfigurationBundle savedBundle = this.bundleService.insert(configurationBundle);
            this.bundleService.applyConfigurationBundle(savedBundle, this.userService.getAdminUser());
        } catch (IOException e) {
            LOG.error("Unable to import content pack for threat intel plugin: ", e);
        }
    }
}
