// eslint-disable-next-line no-unused-vars, import/default, no-unused-vars
import webpackEntry from 'webpack-entry';

import { PluginManifest, PluginStore } from 'graylog-web-plugin/plugin';
import ThreatIntelPluginConfig from 'components/ThreatIntelPluginConfig';

import { SpamhausEDROPAdapterDocumentation, SpamhausEDROPAdapterFieldSet, SpamhausEDROPAdapterSummary } from 'components/adapters/spamhaus-edrop';
import { TorExitNodeAdapterDocumentation, TorExitNodeAdapterFieldSet, TorExitNodeAdapterSummary } from 'components/adapters/torexitnode';
import { WhoisAdapterDocumentation, WhoisAdapterFieldSet, WhoisAdapterSummary } from 'components/adapters/whois/index';

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
      type: 'spamhaus-edrop',
      displayName: 'Spamhaus (E)DROP',
      formComponent: SpamhausEDROPAdapterFieldSet,
      summaryComponent: SpamhausEDROPAdapterSummary,
      documentationComponent: SpamhausEDROPAdapterDocumentation,
    },
    {
      type: 'torexitnode',
      displayName: 'Tor Exit Node',
      formComponent: TorExitNodeAdapterFieldSet,
      summaryComponent: TorExitNodeAdapterSummary,
      documentationComponent: TorExitNodeAdapterDocumentation,
    },
    {
      type: 'whois',
      displayName: 'Whois for IPs',
      formComponent: WhoisAdapterFieldSet,
      summaryComponent: WhoisAdapterSummary,
      documentationComponent: WhoisAdapterDocumentation,
    },
  ],
}));
