import React from 'react';
import PropTypes from 'prop-types';

import { Input } from 'components/bootstrap';

const Registries = {
  AFRINIC: 'AFRINIC (Africa)',
  APNIC: 'APNIC (Asia/Pacific)',
  ARIN: 'ARIN (North America)',
  LACNIC: 'LACNIC (South America)',
  RIPENCC: 'RIPENCC (Europe)',
};

const WhoisAdapterFieldSet = ({ handleFormEvent, validationState, validationMessage, config}) => (
  <fieldset>
    <Input type="select"
           id="registry"
           name="registry"
           label="Registry"
           autoFocus
           required
           onChange={handleFormEvent}
           help={validationMessage('registry', 'The registry used for the initial lookup, should be the closest to your location.')}
           bsStyle={validationState('registry')}
           value={config.registry}
           labelClassName="col-sm-3"
           wrapperClassName="col-sm-9">
      {Object.keys(Registries).map(r => <option value={r}>{Registries[r]}</option>)}
    </Input>
  </fieldset>
);

WhoisAdapterFieldSet.propTypes = {
  config: PropTypes.shape({
    registry: PropTypes.string.isRequired,
  }).isRequired,
  handleFormEvent: PropTypes.func.isRequired,
  validationMessage: PropTypes.func.isRequired,
  validationState: PropTypes.func.isRequired,
};

export default WhoisAdapterFieldSet;
