package org.graylog.plugins.threatintel;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

public class ThreatIntelPluginMetaData implements PluginMetaData {
    private static final String PLUGIN_PROPERTIES = "org.graylog.plugins.graylog-plugin-threatintel/graylog-plugin.properties";

    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.threatintel.ThreatIntelPlugin";
    }

    @Override
    public String getName() {
        return "Threat Intelligence Plugin";
    }

    @Override
    public String getAuthor() {
        return "Graylog, Inc <lennart@graylog.com>";
    }

    @Override
    public URI getURL() {
        return URI.create("https://github.com/Graylog2/graylog-plugin-threatintel");
    }

    @Override
    public Version getVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "version", Version.from(0, 8, 0));
    }

    @Override
    public String getDescription() {
        return "Threat intelligence database lookup functions for the Graylog Pipeline Processor";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.fromPluginProperties(getClass(), PLUGIN_PROPERTIES, "graylog.version", Version.from(2, 1, 0));
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }

}
