'use strict';

/*
 *  To encrypt your secrets use the following steps:
 *
 *  1. Create or use an existing KMS Key - http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html
 *
 *  2. Click the "Enable Encryption Helpers" checkbox
 *
 *  3. Paste <your logzio customer token> into the kmsEncryptedCustomerToken environment variable and click encrypt
*/

const AWS = require('aws-sdk');
const http = require('https');
const zlib = require('zlib');


// logzio url, token and tag configuration
// user needs to edit environment variables when creating function via blueprint
// logzioHostName, e.g. logs-01.logzio.com
// logziotype, e.g. CloudWatch2logzio
const logzioConfiguration = {
    hostName: process.env.logzioHostName,
    hostPort: process.env.logzioHostPort,
    logType: process.env.logzioLogType
};

// use KMS to decrypt customer token in kmsEncryptedCustomerToken environment variable
const decryptParams = {
    CiphertextBlob: new Buffer(process.env.kmsEncryptedCustomerToken, 'base64'),
};

const kms = new AWS.KMS({ apiVersion: '2014-11-01' });
process.stderr.write(process.env.kmsEncryptedCustomerToken);
console.log(process.env.kmsEncryptedCustomerToken);
kms.decrypt(decryptParams, (error, data) => {
    if (error) {
        logzioConfiguration.tokenInitError = error;
        console.log(error);
    } else {
        logzioConfiguration.customerToken = data.Plaintext.toString('ascii');
    }
});

// entry point
exports.handler = (event, context, callback) => {
    const payload = new Buffer(event.awslogs.data, 'base64');

    // converts the event to a valid JSON object with the sufficient infomation required
    function parseEvent(logEvent, logGroupName, logStreamName) {
        var theMessage = logEvent.message.substring(0, logEvent.message.length);
        return {
            message: theMessage,
            logGroupName,
            logStreamName,
            "@timestamp": new Date(logEvent.timestamp).toISOString()
        };
    }

    // joins all the events to a single event
    // and sends to logzio using bulk endpoint
    function postEventsTologzio(parsedEvents) {
        if (!logzioConfiguration.customerToken) {
            if (logzioConfiguration.tokenInitError) {
                console.log('error in decrypt the token. Not retrying.');
                return callback(logzioConfiguration.tokenInitError);
            }
            console.log('Cannot flush logs since authentication token has not been initialized yet. Trying again in 100 ms.');
            setTimeout(() => postEventsTologzio(parsedEvents), 100);
            return;
        }

        // get all the events, stringify them and join them
        // with the new line character which can be sent to logzio
        // via bulk endpoint
        const finalEvent = parsedEvents.map(JSON.stringify).join('\n');

        // creating logzioURL at runtime, so that user can change the tag or customer token in the go
        // by modifying the current script
        // create request options to send logStream
        try {
            const options = {
                hostname: logzioConfiguration.hostName,
                port: logzioConfiguration.hostPort,
                path: `/?token=${logzioConfiguration.customerToken}&type=${encodeURIComponent(logzioConfiguration.logType)}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': finalEvent.length,
                },
            };

            const req = http.request(options, (res) => {
                res.on('data', (data) => {
                    console.log(data);
                    const result = JSON.parse(data.toString());
                    if (result.response === 'ok') {
                        callback(null, 'all events are sent to logzio');
                    } else {
                        console.log(result.response);
                    }
                });
                res.on('end', () => {
                    console.log('No more data in response.');
                    callback();
                });
            });

            req.on('error', (err) => {
                console.log('problem with request:', err.toString());
                callback(err);
            });

            // write data to request body
            req.write(finalEvent);
            req.end();
        } catch (ex) {
            console.log(ex.message);
            callback(ex.message);
        }
    }

    zlib.gunzip(payload, (error, result) => {
        if (error) {
            callback(error);
        } else {
            const resultParsed = JSON.parse(result.toString('ascii'));
            const parsedEvents = resultParsed.logEvents.map((logEvent) =>
                    parseEvent(logEvent, resultParsed.logGroup, resultParsed.logStream));

            postEventsTologzio(parsedEvents);
        }
    });
};
