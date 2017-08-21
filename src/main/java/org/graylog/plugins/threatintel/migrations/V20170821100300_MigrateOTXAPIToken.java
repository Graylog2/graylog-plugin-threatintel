package org.graylog.plugins.threatintel.migrations;

import org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.lookup.adapters.HTTPJSONPathDataAdapter;
import org.graylog2.lookup.db.DBDataAdapterService;
import org.graylog2.lookup.dto.DataAdapterDto;
import org.graylog2.lookup.events.DataAdaptersUpdated;
import org.graylog2.migrations.Migration;
import org.graylog2.plugin.cluster.ClusterConfigService;

import javax.inject.Inject;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class V20170821100300_MigrateOTXAPIToken extends Migration {
    private static final String OTX_DATA_ADAPTER_NAME = "otx-ip";

    private final ClusterConfigService clusterConfigService;
    private final DBDataAdapterService dbDataAdapterService;
    private final ClusterEventBus clusterBus;

    @Inject
    public V20170821100300_MigrateOTXAPIToken(ClusterConfigService clusterConfigService,
                                              DBDataAdapterService dbDataAdapterService,
                                              ClusterEventBus clusterBus) {
        this.clusterConfigService = clusterConfigService;
        this.dbDataAdapterService = dbDataAdapterService;
        this.clusterBus = clusterBus;
    }

    @Override
    public ZonedDateTime createdAt() {
        return ZonedDateTime.parse("2017-08-21T10:03:00Z");
    }

    @Override
    public void upgrade() {
        final ThreatIntelPluginConfiguration pluginConfig = clusterConfigService.get(ThreatIntelPluginConfiguration.class);
        if (pluginConfig == null || pluginConfig.otxApiKey() == null) {
            return;
        }

        final String otxApiKey = pluginConfig.otxApiKey();
        final DataAdapterDto dataAdapterDto = this.dbDataAdapterService.get(OTX_DATA_ADAPTER_NAME)
                .orElseThrow(() -> new IllegalStateException("OTX data adapter not present when trying to add API token."));

        if (dataAdapterDto.config() == null || dataAdapterDto.config().type().equals(HTTPJSONPathDataAdapter.NAME)) {
            throw new IllegalStateException("AlienVault OTX Data Adapter <" + OTX_DATA_ADAPTER_NAME + "> does not contain config or config has wrong type.");
        }

        final HTTPJSONPathDataAdapter.Config config = (HTTPJSONPathDataAdapter.Config)dataAdapterDto.config();
        final Map<String, String> newHeaders = new HashMap<>(config.headers() != null ? config.headers() : Collections.emptyMap());
        newHeaders.put("X-OTX-API-KEY", otxApiKey);
        final HTTPJSONPathDataAdapter.Config.Builder updatedConfigBuilder = HTTPJSONPathDataAdapter.Config.builder()
                .type(config.type())
                .singleValueJSONPath(config.singleValueJSONPath())
                .url(config.url())
                .userAgent(config.userAgent())
                .headers(newHeaders);
        config.multiValueJSONPath().ifPresent(updatedConfigBuilder::multiValueJSONPath);

        final DataAdapterDto saved = dbDataAdapterService.save(DataAdapterDto.builder()
                .id(dataAdapterDto.id())
                .config(updatedConfigBuilder.build())
                .description(dataAdapterDto.description())
                .name(dataAdapterDto.name())
                .contentPack(dataAdapterDto.contentPack())
                .build());
        clusterBus.post(DataAdaptersUpdated.create(saved.id()));
    }
}
