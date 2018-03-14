import React from 'react';
import PropTypes from 'prop-types';

class OTXAdapterSummary extends React.Component {
  static propTypes = {
    dataAdapter: PropTypes.shape({
      config: PropTypes.shape({
        indicator: PropTypes.string.isRequired,
        api_key: PropTypes.string,
        api_url: PropTypes.string.isRequired,
        http_user_agent: PropTypes.string.isRequired,
        http_connect_timeout: PropTypes.number.isRequired,
        http_write_timeout: PropTypes.number.isRequired,
        http_read_timeout: PropTypes.number.isRequired,
      }),
    }),
  };

  render() {
    const { config } = this.props.dataAdapter;

    return (
      <dl>
        <dt>Indicator</dt>
        <dd>{config.indicator}</dd>
        <dt>OTX API Key</dt>
        <dd>{config.api_key || 'n/a'}</dd>
        <dt>OTX API URL</dt>
        <dd>{config.api_url}</dd>
        <dt>HTTP User-Agent</dt>
        <dd>{config.http_user_agent}</dd>
        <dt>HTTP Connect Timeout</dt>
        <dd>{config.http_connect_timeout} ms</dd>
        <dt>HTTP Write Timeout</dt>
        <dd>{config.http_write_timeout} ms</dd>
        <dt>HTTP Read Timeout</dt>
        <dd>{config.http_read_timeout} ms</dd>
      </dl>
    );
  }
}

export default OTXAdapterSummary;
