import React from 'react';

const WhoisAdapterDocumentation = () => {
  const style = { marginBottom: 10 };

  return (
    <div>
      <p style={style}>
        The whois IP lookup data adapter can request network ownership information for an IP address.
      </p>

      <h3 style={style}>Configuration</h3>

      <h5 style={style}>Registry</h5>

      <p style={style}>
        The whois registry host that should be used for the lookup requests. The default value of <code>ARIN</code> should
        work in most cases because it is returning redirects to other servers if it cannot answer a request.
      </p>

      <h5 style={style}>Connect timeout</h5>

      <p style={style}>
        The connection timeout for the socket to the whois server in milliseconds. If you set this to a
        high value, it can affect your processing peformance.
      </p>

      <h5 style={style}>Read timeout</h5>

      <p style={style}>
        The connection read timeout for the socket to the whois server in milliseconds. If you set this to a
        high value, it can affect your processing peformance.
      </p>
    </div>
  );
};

export default WhoisAdapterDocumentation;
