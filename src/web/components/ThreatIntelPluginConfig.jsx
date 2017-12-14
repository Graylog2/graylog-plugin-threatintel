import PropTypes from 'prop-types';
import React from 'react';
import { Alert, Button } from 'react-bootstrap';
import { LinkContainer } from 'react-router-bootstrap';

import { BootstrapModalForm, Input } from 'components/bootstrap';
import { IfPermitted } from 'components/common';
import ObjectUtils from 'util/ObjectUtils';
import Routes from 'routing/Routes';

const ThreatIntelPluginConfig = React.createClass({
  propTypes: {
    config: PropTypes.object,
    updateConfig: PropTypes.func.isRequired,
  },

  getDefaultProps() {
    return {
      config: {
        otx_enabled: false,
        tor_enabled: false,
        spamhaus_enabled: false,
        abusech_ransom_enabled: false,
      },
    };
  },

  getInitialState() {
    return {
      config: ObjectUtils.clone(this.props.config),
    };
  },

  componentWillReceiveProps(newProps) {
    this.setState({ config: ObjectUtils.clone(newProps.config) });
  },

  _updateConfigField(field, value) {
    const update = ObjectUtils.clone(this.state.config);
    update[field] = value;
    this.setState({ config: update });
  },

  _onCheckboxClick(field, ref) {
    return () => {
      this._updateConfigField(field, this.refs[ref].getChecked());
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

          <dt>AlienVault OTX:</dt>
          <dd>{this.state.config.otx_enabled === true ? 'Enabled' : 'Disabled'}</dd>
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
                   ref="torEnabled"
                   label="Allow Tor exit node lookups?"
                   help="Enable to include Tor exit node lookup in global pipeline function, disabling also stops refreshing the data."
                   name="tor_enabled"
                   checked={this.state.config.tor_enabled}
                   onChange={this._onCheckboxClick('tor_enabled', 'torEnabled')}/>

            <Input type="checkbox"
                   id="spamhaus-checkbox"
                   ref="spamhausEnabled"
                   label="Allow Spamhaus DROP/EDROP lookups?"
                   help="Enable to include Spamhaus lookup in global pipeline function, disabling also stops refreshing the data."
                   name="tor_enabled"
                   checked={this.state.config.spamhaus_enabled}
                   onChange={this._onCheckboxClick('spamhaus_enabled', 'spamhausEnabled')}/>

            <Input type="checkbox"
                   id="abusech-checkbox"
                   ref="abusechRansomEnabled"
                   label="Allow Abuse.ch Ransomware tracker lookups?"
                   help="Enable to include Abuse.ch Ransomware tracker lookup in global pipeline function, disabling also stops refreshing the data."
                   name="tor_enabled"
                   checked={this.state.config.abusech_ransom_enabled}
                   onChange={this._onCheckboxClick('abusech_ransom_enabled', 'abusechRansomEnabled')}/>

            <Input type="checkbox"
                   id="otx-checkbox"
                   ref="otxEnabled"
                   label="Allow AlienVault OTX lookups?"
                   help="Enable to include AlienVault OTX lookup in global pipeline function."
                   name="otx_enabled"
                   checked={this.state.config.otx_enabled}
                   onChange={this._onCheckboxClick('otx_enabled', 'otxEnabled')}/>
          </fieldset>
        </BootstrapModalForm>
      </div>
    );
  },
});

export default ThreatIntelPluginConfig;