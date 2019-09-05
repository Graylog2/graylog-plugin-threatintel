import React from 'react';

import { Alert } from 'components/graylog';

const AbuseChRansomAdapterDocumentation = () => {
  return (
    <div>
      <p>The <a href="https://ransomwaretracker.abuse.ch/blocklist/" target="_blank" rel="noopener noreferrer">abuse.ch ransomware tracker</a> offers various types of blocklists that allows you to block Ransomware botnet C&amp;C traffic.</p>

      <Alert style={{ marginBottom: 10 }} bsStyle="info">
        <h4 style={{ marginBottom: 10 }}>Limitations</h4>
        <p>Currently only the combined blocklists are supported.</p>
        <p>For support of individual blocklists, please visit our support channels.</p>
      </Alert>

    </div>
  );
};

export default AbuseChRansomAdapterDocumentation;
