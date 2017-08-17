import React from 'react';
import PropTypes from 'prop-types';

const SpamhausEDROPAdapterFieldSet = ({ handleFormEvent, validationState, validationMessage, config}) => (
  <fieldset/>
);

SpamhausEDROPAdapterFieldSet.propTypes = {
  config: PropTypes.shape({}).isRequired,
  handleFormEvent: PropTypes.func.isRequired,
  validationMessage: PropTypes.func.isRequired,
  validationState: PropTypes.func.isRequired,
};

export default SpamhausEDROPAdapterFieldSet;
