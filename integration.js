'use strict';

const request = require('postman-request');
const config = require('./config/config');
const async = require('async');
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

  Logger.debug(entities);
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

    Logger.trace(requestOptions);

    if (entity.type === 'cve') {
      requestOptions.uri = url + '/vulnerabilities/' + entity.value + '/landing';
    } else if (options.lookups.value.includes('threatActors')) {
      requestOptions.uri = url + '/actors/' + entity.value + '/landing';
    } else if (options.lookups.value.includes('mitre')) {
      requestOptions.uri = url + '/attacks/' + entity.value + '/landing';
    }else {
      cb({ detail: 'Unknown entity type received', err: new Error('Unknown lookup, please check your lookup options') });
      return;
    }

    Logger.trace({ requestOptions }, 'Request Options');

    tasks.push(function(done) {
      requestWithDefaults(requestOptions, function(error, res, body) {
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
        let summary = [];
        if(result.body.combined.description){
          summary.push(result.body.combined.description); 
        }

        lookupResults.push({
          entity: result.entity,
          data: {
            summary: summary,
            details: result.body.combined
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
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

  if (res.statusCode === 404){
    return {
      entity: entity,
      body: null,
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
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage,
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(
    errors,
    options,
    "apiKey",
    "You must provide a valid API Key"
  );
  callback(null, errors);
}

module.exports = {
  doLookup,
  validateOptions,
  startup
};