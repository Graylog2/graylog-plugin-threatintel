import PropTypes from 'prop-types';
import React from 'react';
import { TimeUnit } from 'components/common';

class AbuseChRansomAdapterSummary extends React.Component {
  static propTypes = {
    dataAdapter: PropTypes.object.isRequired,
  };

  render() {
    const config = this.props.dataAdapter.config;
    const blocklistType = {
      DOMAINS: 'Domain blocklist',
      URLS: 'URL blocklist',
      IPS: 'IP blocklist',
    };
    return (<dl>
      <dt>Blocklist type</dt>
      <dd>{blocklistType[config.blocklist_type]}</dd>
      <dt>Update interval</dt>
      <dd><TimeUnit value={config.refresh_interval} unit={config.refresh_interval_unit} /></dd>
    </dl>);
  }
}

export default AbuseChRansomAdapterSummary;
