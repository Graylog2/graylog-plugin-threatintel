/* eslint-disable react/no-unescaped-entities, no-template-curly-in-string */
import React from 'react';

import { ExternalLink } from 'components/common';

const GreynoiseNoiseAdapterDocumentation = React.createClass({
  render() {
    const style = { marginBottom: 10 };
    return (
      <div>
        <p style={style}>
          The Greynoise data adapter uses the <ExternalLink href="https://greynoise.io/">Greynoise Noise API</ExternalLink> to
          identify untargeted, widespread, and opportunistic scan and attack activity that reaches every server directly connected
          to the Internet
        </p>

        <h3 style={style}>Configuration</h3>

        <h5 style={style}>Greynoise API Key</h5>

        <p style={style}>
          An API key is required to communicate with the Greynoise APIs. You can get yours at
          &nbsp;<a href="https://greynoise.io/" target="_blank">https://greynoise.io/</a>.
        </p>
      </div>
    );
  },
});

export default GreynoiseNoiseAdapterDocumentation;
