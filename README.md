# logzio-lambda

Send logs to Logz.io using Lambda function 
The function is running on Node.js 4.3

To use this function you will need to provide the following environment variables:
```
kmsEncryptedCustomerToken - <logzioToken> - need to be encrypted with the KMS key
logzioHostPort - 8071
logzioLogType - VPC_FLOW 
logzioHostName - listener.logz.io
```
