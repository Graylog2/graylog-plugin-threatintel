import React from 'react';
import PropTypes from 'prop-types';

const WhoisAdapterSummary = ({ dataAdapter }) => {
  const { config } = dataAdapter;

  return (<dl>
    <dt>Registry</dt>
    <dd>{config.registry}</dd>
    <dt>Connect timeout</dt>
    <dd>{config.connect_timeout} ms</dd>
    <dt>Read timeout</dt>
    <dd>{config.read_timeout} ms</dd>
  </dl>);
};

WhoisAdapterSummary.propTypes = {
  dataAdapter: PropTypes.shape({
    config: PropTypes.shape({
      registry: PropTypes.string.isRequired,
      connect_timeout: PropTypes.number.isRequired,
      read_timeout: PropTypes.number.isRequired,
    }),
  }).isRequired,
};

export default WhoisAdapterSummary;
