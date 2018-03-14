import React from 'react';
import PropTypes from 'prop-types';

import { Input } from 'components/bootstrap';

class WhoisAdapterFieldSet extends React.Component {
  static propTypes = {
    config: PropTypes.shape({
      connect_timeout: PropTypes.number.isRequired,
      read_timeout: PropTypes.number.isRequired,
    }).isRequired,
    handleFormEvent: PropTypes.func.isRequired,
    validationMessage: PropTypes.func.isRequired,
    validationState: PropTypes.func.isRequired,
  };

  render() {
    const { config } = this.props;

    return (
      <fieldset>
        <Input type="number"
               id="connect_timeout"
               name="connect_timeout"
               label="Connect timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('connect_timeout', 'WHOIS connection timeout in milliseconds.')}
               bsStyle={this.props.validationState('connect_timeout')}
               value={config.connect_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
        <Input type="number"
               id="read_timeout"
               name="read_timeout"
               label="Read timeout"
               required
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('read_timeout', 'WHOIS connection read timeout in milliseconds.')}
               bsStyle={this.props.validationState('read_timeout')}
               value={config.read_timeout}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
      </fieldset>
    );
  }
}

export default WhoisAdapterFieldSet;
