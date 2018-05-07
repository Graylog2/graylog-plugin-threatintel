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

        <p style={style}>
          TODO
        </p>
      </div>
    );
  },
});

export default GreynoiseNoiseAdapterDocumentation;
