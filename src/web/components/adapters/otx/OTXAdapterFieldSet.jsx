import React from 'react';
import PropTypes from 'prop-types';
import lodash from 'lodash';

import { Input } from 'components/bootstrap';
import { Select } from 'components/common';

const OTX_INDICATORS = [
  { label: 'IP Auto-Detect', value: 'IPAutoDetect' },
  { label: 'IP v4', value: 'IPv4' },
  { label: 'IP v6', value: 'IPv6' },
  { label: 'Domain', value: 'domain' },
  { label: 'Hostname', value: 'hostname' },
  { label: 'File', value: 'file' },
  { label: 'URL', value: 'url' },
  { label: 'CVE', value: 'cve' },
  { label: 'NIDS', value: 'nids' },
  { label: 'Correlation-Rule', value: 'correlation-rule' },
];

const OTX_HTTP_SCHEMES = [
  { label: 'HTTPS', value: 'https' },
  { label: 'HTTP', value: 'http' },
];

const OTXAdapterFieldSet = React.createClass({
  propTypes: {
    config: PropTypes.shape({
      indicator: PropTypes.string.isRequired,
      api_key: PropTypes.string,
      http_user_agent: PropTypes.string.isRequired,
      otx_host: PropTypes.string.isRequired,
      otx_port: PropTypes.number.isRequired,
      otx_scheme: PropTypes.string.isRequired,
      http_connect_timeout: PropTypes.number.isRequired,
      http_write_timeout: PropTypes.number.isRequired,
      http_read_timeout: PropTypes.number.isRequired,
    }).isRequired,
    updateConfig: PropTypes.func.isRequired,
    handleFormEvent: PropTypes.func.isRequired,
    validationState: PropTypes.func.isRequired,
    validationMessage: PropTypes.func.isRequired,
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
        <Input id="indicator"
               label="Indicator"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('indicator', 'The OTX indicator type that should be used for lookups.')}
               bsStyle={this.props.validationState('indicator')}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9">
          <Select placeholder="Select indicator"
                  clearable={false}
                  options={OTX_INDICATORS}
                  matchProp="value"
                  onChange={this.handleSelect('indicator')}
                  value={config.indicator} />
        </Input>
        <Input type="text"
               id="api_key"
               name="api_key"
               label="OTX API Key"
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('api_key', 'Your OTX API key.')}
               bsStyle={this.props.validationState('api_key')}
               value={config.api_key}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="text"
               id="http_user_agent"
               name="http_user_agent"
               label="HTTP User-Agent"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('http_user_agent', 'The User-Agent header that should be used for the HTTP request.')}
               bsStyle={this.props.validationState('http_user_agent')}
               value={config.http_user_agent}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="text"
               id="otx_host"
               name="otx_host"
               label="OTX Hostname"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('otx_host', 'Hostname of the OTX server.')}
               bsStyle={this.props.validationState('otx_host')}
               value={config.otx_host}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="text"
               id="otx_port"
               name="otx_port"
               label="OTX Port"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('otx_port', 'Port for the connection to the server.')}
               bsStyle={this.props.validationState('otx_port')}
               value={config.otx_port}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input id="otx_scheme"
               label="HTTP Scheme"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('otx_scheme', 'The registry used for the initial lookup, should be the closest to your location.')}
               bsStyle={this.props.validationState('otx_scheme')}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9">
          <Select placeholder="Select indicator"
                  clearable={false}
                  options={OTX_HTTP_SCHEMES}
                  matchProp="value"
                  onChange={this.handleSelect('otx_scheme')}
                  value={config.otx_scheme} />
        </Input>
        <Input type="number"
               id="http_connect_timeout"
               name="http_connect_timeout"
               label="HTTP Connect Timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('http_connect_timeout', 'HTTP connection timeout in milliseconds.')}
               bsStyle={this.props.validationState('http_connect_timeout')}
               value={config.http_connect_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="number"
               id="http_write_timeout"
               name="http_write_timeout"
               label="HTTP Write Timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('http_write_timeout', 'HTTP write timeout in milliseconds.')}
               bsStyle={this.props.validationState('http_write_timeout')}
               value={config.http_write_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="number"
               id="http_read_timeout"
               name="http_read_timeout"
               label="HTTP Read Timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('http_read_timeout', 'HTTP read timeout in milliseconds.')}
               bsStyle={this.props.validationState('http_read_timeout')}
               value={config.http_read_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
      </fieldset>
    );
  },
});

export default OTXAdapterFieldSet;
