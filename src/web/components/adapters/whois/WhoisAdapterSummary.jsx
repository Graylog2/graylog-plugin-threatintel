import React from 'react';

const WhoisAdapterSummary = ({ dataAdapter }) => {
  const { config } = dataAdapter;

  return (<dl>
    <dt>Registry</dt>
    <dd>{config.registry}</dd>
  </dl>);
};

export default WhoisAdapterSummary;
