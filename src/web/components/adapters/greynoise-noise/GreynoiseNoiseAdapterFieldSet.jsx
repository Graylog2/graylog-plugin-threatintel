import React from 'react';
import PropTypes from 'prop-types';
import lodash from 'lodash';

import { Input } from 'components/bootstrap';

const GreynoiseNoiseAdapterFieldSet = React.createClass({
  propTypes: {
    config: PropTypes.shape({
      api_key: PropTypes.string
    }).isRequired,
    updateConfig: PropTypes.func.isRequired,
    handleFormEvent: PropTypes.func.isRequired,
    validationState: PropTypes.func.isRequired,
    validationMessage: PropTypes.func.isRequired,
  },

  handleSelect(fieldName) {
    return (selectedIndicator) => {
      const config = lodash.cloneDeep(this.props.config);
      config[fieldName] = selectedIndicator;
      this.props.updateConfig(config);
    };
  },

  render() {
    const { config } = this.props;

    return (
      <fieldset>
        <Input type="text"
               id="api_key"
               name="api_key"
               label="Greynoise API Key"
               onChange={this.props.handleFormEvent}
               help={this.props.validationMessage('api_key', 'Your Greynoise API key.')}
               bsStyle={this.props.validationState('api_key')}
               value={config.api_key}
               labelClassName="col-sm-3"
               wrapperClassName="col-sm-9" />
      </fieldset>
    );
  },
});

export default GreynoiseNoiseAdapterFieldSet;
