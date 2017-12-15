import React from 'react';
import PropTypes from 'prop-types';
import lodash from 'lodash';

import { Input } from 'components/bootstrap';
import { Select } from 'components/common';

const WHOIS_REGISTRIES = [
  { value: 'AFRINIC', label: 'AFRINIC (Africa)' },
  { value: 'APNIC', label: 'APNIC (Asia/Pacific)' },
  { value: 'ARIN', label: 'ARIN (North America)' },
  { value: 'LACNIC', label: 'LACNIC (South America)' },
  { value: 'RIPENCC', label: 'RIPENCC (Europe)' },
];

const WhoisAdapterFieldSet = React.createClass({
  propTypes: {
    config: PropTypes.shape({
      registry: PropTypes.string.isRequired,
      connect_timeout: PropTypes.number.isRequired,
      read_timeout: PropTypes.number.isRequired,
    }).isRequired,
    handleFormEvent: PropTypes.func.isRequired,
    validationMessage: PropTypes.func.isRequired,
    validationState: PropTypes.func.isRequired,
  },

  handleSelect(fieldName) {
    return (selectedIndicator) => {
      const config = lodash.cloneDeep(this.props.config);
      config[fieldName] = selectedIndicator;
      this.props.updateConfig(config);
    };
  },

  render() {
    const { config } = this.props;

    return (
      <fieldset>
        <Input id="registry"
               label="Registry"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('registry', 'The registry used for the initial lookup, should be the closest to your location.')}
               bsStyle={this.props.validationState('registry')}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9">
          <Select placeholder="Select registry"
                  clearable={false}
                  options={WHOIS_REGISTRIES}
                  matchProp="value"
                  onChange={this.handleSelect('registry')}
                  value={config.registry} />
        </Input>
        <Input type="number"
               id="connect_timeout"
               name="connect_timeout"
               label="Connect timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('connect_timeout', 'WHOIS connection timeout in milliseconds.')}
               bsStyle={this.props.validationState('connect_timeout')}
               value={config.connect_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="number"
               id="read_timeout"
               name="read_timeout"
               label="Read timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('read_timeout', 'WHOIS connection read timeout in milliseconds.')}
               bsStyle={this.props.validationState('read_timeout')}
               value={config.read_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
      </fieldset>
    );
  },
});

export default WhoisAdapterFieldSet;
