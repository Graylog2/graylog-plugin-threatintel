import React from 'react';
import PropTypes from 'prop-types';

const OTXAdapterSummary = React.createClass({
  propTypes: {
    dataAdapter: PropTypes.shape({
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
      }),
    }),
  },

  render() {
    const { config } = this.props.dataAdapter;

    return (
      <dl>
        <dt>Indicator</dt>
        <dd>{config.indicator}</dd>
        <dt>OTX API Key</dt>
        <dd>{config.api_key || 'n/a'}</dd>
        <dt>HTTP User-Agent</dt>
        <dd>{config.http_user_agent}</dd>
        <dt>OTX Hostname</dt>
        <dd>{config.otx_host}</dd>
        <dt>OTX Port</dt>
        <dd>{config.otx_port}</dd>
        <dt>HTTP Scheme</dt>
        <dd>{config.otx_scheme}</dd>
        <dt>HTTP Connect Timeout</dt>
        <dd>{config.http_connect_timeout} ms</dd>
        <dt>HTTP Write Timeout</dt>
        <dd>{config.http_write_timeout} ms</dd>
        <dt>HTTP Read Timeout</dt>
        <dd>{config.http_read_timeout} ms</dd>
      </dl>
    );
  },
});

export default OTXAdapterSummary;
