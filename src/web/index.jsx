// eslint-disable-next-line no-unused-vars

import webpackEntry from 'webpack-entry';

import packageJson from '../../package.json';
import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';

PluginStore.register(new PluginManifest(packageJson, {
    systemConfigurations: [
        {
            component: ThreatIntelPluginConfig,
            configType: 'org.graylog.plugins.graylog-plugin-threatintel.ThreatIntelConfiguration',
        },
    ],
}));