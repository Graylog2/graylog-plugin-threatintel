import PropTypes from 'prop-types';
import React from 'react';
import createReactClass from 'create-react-class';

import { Button } from 'components/graylog';
import { BootstrapModalForm, Input } from 'components/bootstrap';
import { IfPermitted } from 'components/common';
import ObjectUtils from 'util/ObjectUtils';

const ThreatIntelPluginConfig = createReactClass({
  displayName: 'ThreatIntelPluginConfig',

  propTypes: {
    config: PropTypes.object,
    updateConfig: PropTypes.func.isRequired,
  },

  getDefaultProps() {
    return {
      config: {
        tor_enabled: false,
        spamhaus_enabled: false,
        abusech_ransom_enabled: false,
      },
    };
  },

  getInitialState() {
    const { config } = this.props;

    return {
      config: ObjectUtils.clone(config),
    };
  },

  componentWillReceiveProps(newProps) {
    this.setState({ config: ObjectUtils.clone(newProps.config) });
  },

  _updateConfigField(field, value) {
    const { config } = this.state;
    const update = ObjectUtils.clone(config);
    update[field] = value;
    this.setState({ config: update });
  },

  _onCheckboxClick(field, ref) {
    return () => {
      this._updateConfigField(field, this[ref].getChecked());
    };
  },

  _onSelect(field) {
    return (selection) => {
      this._updateConfigField(field, selection);
    };
  },

  _onUpdate(field) {
    return (e) => {
      this._updateConfigField(field, e.target.value);
    };
  },

  _openModal() {
    this.threatintelConfigModal.open();
  },

  _closeModal() {
    this.threatintelConfigModal.close();
  },

  _resetConfig() {
    // Reset to initial state when the modal is closed without saving.
    this.setState(this.getInitialState());
  },

  _saveConfig() {
    this.props.updateConfig(this.state.config).then(() => {
      this._closeModal();
    });
  },

  render() {
    return (
      <div>
        <h3>Threat Intelligence Lookup Configuration</h3>

        <p>
          Configuration for threat intelligence lookup plugin.
        </p>

        <dl className="deflist">
          <dt>Tor exit nodes:</dt>
          <dd>{this.state.config.tor_enabled === true ? 'Enabled' : 'Disabled'}</dd>

          <dt>Spamhaus:</dt>
          <dd>{this.state.config.spamhaus_enabled === true ? 'Enabled' : 'Disabled'}</dd>

          <dt>Abuse.ch Ransomware:</dt>
          <dd>{this.state.config.abusech_ransom_enabled === true ? 'Enabled' : 'Disabled'}</dd>
        </dl>

        <IfPermitted permissions="clusterconfigentry:edit">
          <Button bsStyle="info" bsSize="xs" onClick={this._openModal}>Configure</Button>
        </IfPermitted>

        <BootstrapModalForm ref={(ref) => { this.threatintelConfigModal = ref; }}
                            title="Update Threat Intelligence plugin Configuration"
                            onSubmitForm={this._saveConfig}
                            onModalClose={this._resetConfig}
                            submitButtonText="Save">
          <fieldset>
            <Input type="checkbox"
                   id="tor-checkbox"
                   ref={(elem) => { this.torEnabled = elem; }}
                   label="Allow Tor exit node lookups?"
                   help="Enable to include Tor exit node lookup in global pipeline function, disabling also stops refreshing the data."
                   name="tor_enabled"
                   checked={this.state.config.tor_enabled}
                   onChange={this._onCheckboxClick('tor_enabled', 'torEnabled')} />

            <Input type="checkbox"
                   id="spamhaus-checkbox"
                   ref={(elem) => { this.spamhausEnabled = elem; }}
                   label="Allow Spamhaus DROP/EDROP lookups?"
                   help="Enable to include Spamhaus lookup in global pipeline function, disabling also stops refreshing the data."
                   name="tor_enabled"
                   checked={this.state.config.spamhaus_enabled}
                   onChange={this._onCheckboxClick('spamhaus_enabled', 'spamhausEnabled')} />

            <Input type="checkbox"
                   id="abusech-checkbox"
                   ref={(elem) => { this.abusechRansomEnabled = elem; }}
                   label="Allow Abuse.ch Ransomware tracker lookups?"
                   help="Enable to include Abuse.ch Ransomware tracker lookup in global pipeline function, disabling also stops refreshing the data."
                   name="tor_enabled"
                   checked={this.state.config.abusech_ransom_enabled}
                   onChange={this._onCheckboxClick('abusech_ransom_enabled', 'abusechRansomEnabled')} />
          </fieldset>
        </BootstrapModalForm>
      </div>
    );
  },
});

export default ThreatIntelPluginConfig;
