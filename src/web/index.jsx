// eslint-disable-next-line no-unused-vars, import/default, no-unused-vars
import webpackEntry from 'webpack-entry';

import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import ThreatIntelPluginConfig from 'components/ThreatIntelPluginConfig';

import { DSVHTTPAdapterDocumentation, DSVHTTPAdapterFieldSet, DSVHTTPAdapterSummary } from 'components/adapters/DSVhttp';

import packageJson from '../../package.json';

PluginStore.register(new PluginManifest(packageJson, {
  systemConfigurations: [
    {
      component: ThreatIntelPluginConfig,
      configType: 'org.graylog.plugins.threatintel.ThreatIntelPluginConfiguration',
    },
  ],
  lookupTableAdapters: [
    {
      type: 'dsvhttp',
      displayName: 'DSV File from HTTP',
      formComponent: DSVHTTPAdapterFieldSet,
      summaryComponent: DSVHTTPAdapterSummary,
      documentationComponent: DSVHTTPAdapterDocumentation,
    },
  ],
}));
