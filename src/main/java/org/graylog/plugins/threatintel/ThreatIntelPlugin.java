package org.graylog.plugins.threatintel;

import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;

import java.util.Collection;
import java.util.Collections;

public class ThreatIntelPlugin implements Plugin {
    @Override
    public PluginMetaData metadata() {
        return new ThreatIntelPluginMetaData();
    }

    @Override
    public Collection<PluginModule> modules () {
        return Collections.<PluginModule>singletonList(new ThreatIntelPluginModule());
    }
}
