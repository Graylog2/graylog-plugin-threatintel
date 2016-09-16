import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from '../../node_modules/graylog-web-plugin/plugin';
import ThreatIntelPluginConfig from 'components/ThreatIntelPluginConfig';

PluginStore.register(new PluginManifest(packageJson, {
    systemConfigurations: [
        {
            component: ThreatIntelPluginConfig,
            configType: 'org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration',
        },
    ],
}));