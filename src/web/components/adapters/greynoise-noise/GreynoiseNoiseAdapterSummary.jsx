import React from 'react';
import PropTypes from 'prop-types';

const GreynoiseAdapterSummary = React.createClass({
  propTypes: {
    dataAdapter: PropTypes.shape({
      config: PropTypes.shape({
        api_key: PropTypes.string
      }),
    }),
  },

  render() {
    const { config } = this.props.dataAdapter;

    return (
      <dl>
        <dt>Greynoise API Key</dt>
        <dd>{config.api_key || 'n/a'}</dd>
      </dl>
    );
  },
});

export default GreynoiseAdapterSummary;
