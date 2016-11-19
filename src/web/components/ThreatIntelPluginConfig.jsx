import React from 'react';
import { Input, Button } from 'react-bootstrap';
import BootstrapModalForm from 'components/bootstrap/BootstrapModalForm';
import { IfPermitted, Select } from 'components/common';
import ObjectUtils from 'util/ObjectUtils';

const ThreatIntelPluginConfig = React.createClass({
    propTypes: {
        config: React.PropTypes.object,
        updateConfig: React.PropTypes.func.isRequired,
    },

    getDefaultProps() {
        return {
            config: {
                otx_enabled: false,
                otx_api_key: '',
                tor_enabled: false,
                spamhaus_enabled: false,
                abusech_ransom_enabled: false
            },
        };
    },

    getInitialState() {
        return {
            config: ObjectUtils.clone(this.props.config),
        };
    },

    componentWillReceiveProps(newProps) {
        this.setState({config: ObjectUtils.clone(newProps.config)});
    },

    _updateConfigField(field, value) {
        const update = ObjectUtils.clone(this.state.config);
        update[field] = value;
        this.setState({config: update});
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
        this.refs.threatintelConfigModal.open();
    },

    _closeModal() {
        this.refs.threatintelConfigModal.close();
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

                    <dt>AlienVault OTX API key:</dt>
                    <dd>{this.state.config.otx_api_key ? "***********" : "[not set]" }</dd>
                </dl>

                <IfPermitted permissions="clusterconfigentry:edit">
                    <Button bsStyle="info" bsSize="xs" onClick={this._openModal}>Configure</Button>
                </IfPermitted>

                <BootstrapModalForm ref="threatintelConfigModal"
                                    title="Update Threat Intelligence plugin Configuration"
                                    onSubmitForm={this._saveConfig}
                                    onModalClose={this._resetConfig}
                                    submitButtonText="Save">
                    <fieldset>
                        <Input type="checkbox"
                               ref="torEnabled"
                               label="Allow Tor exit node lookups?"
                               help={<span>When enabled, the Tor exit node lookup pipeline functions can be executed.</span>}
                               name="tor_enabled"
                               checked={this.state.config.tor_enabled}
                               onChange={this._onCheckboxClick('tor_enabled', 'torEnabled')}/>

                        <Input type="checkbox"
                               ref="spamhausEnabled"
                               label="Allow Spamhaus DROP/EDROP lookups?"
                               help={<span>When enabled, the Spamhaus pipeline functions can be executed.</span>}
                               name="tor_enabled"
                               checked={this.state.config.spamhaus_enabled}
                               onChange={this._onCheckboxClick('spamhaus_enabled', 'spamhausEnabled')}/>

                        <Input type="checkbox"
                               ref="abusechRansomEnabled"
                               label="Allow Abuse.ch Ransomware tracker lookups?"
                               help={<span>When enabled, the Abuse.ch Ransomware tracker pipeline functions can be executed.</span>}
                               name="tor_enabled"
                               checked={this.state.config.abusech_ransom_enabled}
                               onChange={this._onCheckboxClick('abusech_ransom_enabled', 'abusechRansomEnabled')}/>

                        <Input type="checkbox"
                               ref="otxEnabled"
                               label="Allow AlienVault OTX lookups?"
                               help={<span>When enabled, the AlienVault OTX pipeline functions can be executed.</span>}
                               name="otx_enabled"
                               checked={this.state.config.otx_enabled}
                               onChange={this._onCheckboxClick('otx_enabled', 'otxEnabled')}/>

                        <Input type="text"
                               label="AlienVault OTX API key"
                               help={<span>Note that this will only be used in encrypted connections but stored in plaintext.</span>}
                               name="otx_api_key"
                               value={this.state.config.otx_api_key}
                               onChange={this._onUpdate('otx_api_key')}/>
                    </fieldset>
                </BootstrapModalForm>
            </div>
        );
    },
});

export default ThreatIntelPluginConfig;