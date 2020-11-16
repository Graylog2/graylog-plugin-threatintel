/*
 * Copyright (C) 2020 Graylog, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */
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
