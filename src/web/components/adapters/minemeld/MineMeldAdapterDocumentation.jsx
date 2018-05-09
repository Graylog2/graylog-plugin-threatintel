/* eslint-disable react/no-unescaped-entities */
import React from 'react';
import { Alert } from 'react-bootstrap';

class MineMeldAdapterDocumentation extends React.Component {
  render() {
    return (<div>
      <p>MineMeld is an application provided by Palo Alto. It is open source and free to use. It aggregates threat feeds from multiple disparate sources a set (or sets) of outputs to be utilized by multiple different utilities within your organization. Documentation starts <a href="https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld/" target="_blank">here</a>.</p>

      <Alert style={{ marginBottom: 10 }} bsStyle="info">
        <h4 style={{ marginBottom: 10 }}>Limitations</h4>
        <p>Currently to get this to work you will need to modify the java source file at src/main/java/org/graylog/plugins/threatintel/adapters/minemeld/BlocklistType.java to point to your minemeld instance.</p>
        <p>For the IP block list do not remove the ?tr=1 at the end of the url. This tells minemeld how to format he output.</p>
      </Alert>

    </div>);
  }
}

export default MineMeldAdapterDocumentation;
