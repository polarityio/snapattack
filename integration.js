'use strict';

const request = require('postman-request');
const config = require('./config/config');
const async = require('async');
const _ = require('lodash');
const fs = require('fs');

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.trace({ entities }, 'doLookup');

  entities.forEach((entity) => {
    const url = `https://app.snapattack.com/api/tags`;

    let requestOptions = {
      method: 'GET',
      uri: url,
      headers: {
        'X-API-KEY': options.apiKey,
        Accept: 'application/json'
      },
      json: true
    };

    const lookupType = getLookupType(entity, options);

    if (lookupType === 'cve') {
      requestOptions.uri = url + '/vulnerabilities/' + entity.value + '/landing';
    } else if (lookupType === 'threatActors') {
      requestOptions.uri = url + '/actors/' + entity.value + '/landing';
    } else if (lookupType === 'mitre') {
      requestOptions.uri = url + '/attacks/' + entity.value + '/landing';
    } else {
      cb({
        detail: 'Unknown entity type received',
        err: new Error('Unknown lookup, please check your lookup options')
      });
      return;
    }

    Logger.trace({ requestOptions }, 'Request Options');

    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        Logger.trace({ body, status: res.statusCode });
        let processedResult = handleRestError(error, entity, res, body);

        if (processedResult.error) {
          done(processedResult);
          return;
        }

        done(null, processedResult);
      });
    });
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        const lookupType = getLookupType(result.entity, options);
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: getSummaryTags(lookupType, result.body),
            details: {
              lookupType,
              data: result.body.combined
            }
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function getLookupType(entity, options) {
  if (entity.types.includes('cve')) {
    return 'cve';
  } else if (options.lookups.value === 'threatActors') {
    return 'threatActors';
  } else {
    return 'mitre';
  }
}

function getSummaryTags(lookupType, body) {
  const tags = [];
  if (lookupType === 'cve') {
    tags.push(`CVSS Score: ${_.get(body, 'combined.cvss_3_vector_details.base_score', 'N/A')}`);
    tags.push(
      `Vector: ${_.get(body, 'combined.cvss_3_vector_details.modified_attack_vector', 'N/A')}`
    );
  } else if (lookupType === 'threatActors') {
    tags.push(`Tracked Vulns: ${_.get(body, 'combined.vulnerabilities.length', 0)}`);
    tags.push(`Industries: ${_.get(body, 'combined.industries.length', 0)}`);
  } else {
    tags.push(`Threat Actors: ${_.get(body, 'combined.actors.length', 0)}`);
    tags.push(`Severity: ${_.get(body, 'combined.severity', 0)}`);
  }
  return tags;
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error || !body) {
    return {
      error,
      body,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 404) {
    return {
      entity: entity,
      body: null
    };
  }

  if (res.statusCode !== 200) {
    return {
      error: 'Did not receive HTTP 200 Status Code',
      statusCode: res ? res.statusCode : 'Unknown',
      detail: 'An unexpected error occurred',
      body,
      res
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else {
    result = {
      body,
      errorNumber: body.errorNo,
      error: body.errorMsg,
      detail: body.errorMsg
    };
  }

  return result;
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(errors, options, 'apiKey', 'You must provide a valid API Key');
  callback(null, errors);
}

module.exports = {
  doLookup,
  validateOptions,
  startup
};
