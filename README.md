# @silicon/logger

Robust logging utilities for sending structured logs to Splunk. Environment-agnostic logging module that works in Lambda, Node.js, and other environments.

## Installation

```bash
npm install @silicon/logger
```

## Quick Start

```javascript
const Logger = require('@silicon/logger');

// Create a logger instance with explicit credentials
const logger = new Logger({
  endpoint: 'arn:aws:lambda:us-east-1:123456789:function:splunk-intake',
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  environment: 'dev',
  source: 'My Application'
});

// Or use environment variables
// AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
// AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
const logger2 = new Logger({
  endpoint: process.env.SPLUNK_LAMBDA_ARN,
  environment: 'dev',
  source: 'My Application'
});

// Or use apiKey format
const logger3 = new Logger({
  endpoint: process.env.SPLUNK_LAMBDA_ARN,
  apiKey: 'AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  environment: 'dev',
  source: 'My Application'
});

// Log a message
logger.info('User logged in', { userId: '123' });
```

## Configuration

### Constructor Options

```javascript
const logger = new Logger({
  endpoint: string,              // Required: Splunk Lambda ARN or endpoint URL
  accessKeyId: string,            // Optional: AWS access key ID (or use AWS_ACCESS_KEY_ID env var)
  secretAccessKey: string,        // Optional: AWS secret access key (or use AWS_SECRET_ACCESS_KEY env var)
  apiKey: string,                 // Optional: API key in format "accessKeyId:secretAccessKey" (alternative to separate params)
  environment: string,            // Optional: Environment name (default: 'unknown')
  source: string,                 // Optional: Source system identifier (default: 'Silicon Logger')
  region: string,                 // Optional: AWS region (default: 'us-east-1' or AWS_REGION env var)
  getClientIp: function,          // Optional: Custom function to extract client IP
  getGeolocation: function,       // Optional: Custom function to get geolocation from IP
});
```

### Required Parameters

- **`endpoint`**: The Splunk Lambda ARN (e.g., `arn:aws:lambda:us-east-1:123456789:function:splunk-intake`) or endpoint URL

### Optional Parameters

- **`accessKeyId`**: AWS access key ID. If not provided, will use `AWS_ACCESS_KEY_ID` environment variable or default AWS credentials.
- **`secretAccessKey`**: AWS secret access key. If not provided, will use `AWS_SECRET_ACCESS_KEY` environment variable or default AWS credentials.
- **`apiKey`**: API key in format `"accessKeyId:secretAccessKey"`. Alternative to providing `accessKeyId` and `secretAccessKey` separately. If only one value is provided, it will be used as `accessKeyId` and `secretAccessKey` will be read from `AWS_SECRET_ACCESS_KEY` env var.
- **`environment`**: Environment name (e.g., 'dev', 'prod', 'staging'). Defaults to `process.env.ENV` or 'unknown'.
- **`source`**: Source system identifier. Defaults to 'Silicon Logger'.
- **`region`**: AWS region for Lambda invocation. Defaults to `process.env.AWS_REGION` or 'us-east-1'.
- **`getClientIp`**: Custom function to extract client IP from request context. Signature: `(requestContext) => string | null`
- **`getGeolocation`**: Custom function to get geolocation from IP. Signature: `(ip, requestContext) => object | null`

### Credentials Priority

Credentials are resolved in the following order:
1. Constructor parameters (`accessKeyId`/`secretAccessKey` or `apiKey`)
2. Environment variables (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`)
3. Default AWS credentials (IAM role, `~/.aws/credentials`, etc.)

## Usage Examples

### Basic Logging

```javascript
const Logger = require('@silicon/logger');

const logger = new Logger({
  endpoint: 'arn:aws:lambda:us-east-1:123456789:function:splunk-intake',
  environment: 'prod',
  source: 'My API'
});

// Info log
logger.info('Request processed successfully');

// Warning log
logger.warn('Rate limit approaching', { currentRate: 95, limit: 100 });

// Error log
logger.error('Database connection failed', { error: 'Connection timeout' });

// Debug log
logger.debug('Cache hit', { key: 'user:123', ttl: 3600 });
```

### Logging with Request Context

```javascript
// Express.js example
app.get('/api/users/:id', async (req, res) => {
  const logger = new Logger({
    endpoint: process.env.SPLUNK_LAMBDA_ARN,
    environment: process.env.NODE_ENV,
    source: 'User API'
  });

  // Log with request context
  logger.info('Fetching user', { userId: req.params.id }, req);

  // ... your code ...
});
```

### Lambda Function Usage

The recommended approach is to pass `event` and `context` in the constructor so all logs from that Lambda invocation automatically include Lambda context:

```javascript
const Logger = require('@silicon/logger');

exports.handler = async (event, context) => {
  // Create logger with event and context - all logs will automatically include Lambda context
  const logger = new Logger({
    endpoint: process.env.SPLUNK_LAMBDA_ARN,
    environment: process.env.ENV,
    source: 'Lambda Function',
    event: event,    // Lambda event - used for all logs
    context: context // Lambda context - used for all logs
  });

  // Set request metadata (IP, geolocation) before logging
  const requestId = event.requestContext?.requestId || context.awsRequestId;
  const clientIp = event.requestContext?.identity?.sourceIp;
  
  if (clientIp) {
    // Get geolocation (async)
    const geolocation = await getGeolocation(clientIp);
    logger.setRequestMetadata(requestId, {
      ip: clientIp,
      geolocation: geolocation
    });
  }

  // All logs automatically include Lambda context - no need to pass event/context each time
  logger.info('Lambda invoked', { 
    functionName: context.functionName 
  });

  try {
    // ... your code ...
    logger.info('Processing complete', { result: 'success' });
    logger.debug('Debug information', { step: 'validation' });
  } catch (error) {
    logger.error('Processing failed', error);
    throw error;
  } finally {
    // Clean up request metadata
    logger.cleanupRequest(requestId);
  }
};
```

### Lambda Context Template Example

When you pass `event` and `context` in the constructor, the logger automatically extracts Lambda-specific information and includes it in a nested `lambda` object for **all logs**:

```javascript
const Logger = require('@silicon/logger');

exports.handler = async (event, context) => {
  // Pass event and context in constructor
  const logger = new Logger({
    endpoint: process.env.SPLUNK_LAMBDA_ARN,
    environment: 'prod',
    source: 'My Lambda Function',
    event: event,
    context: context
  });

  // All logs automatically include Lambda context
  logger.info('Request received');
  logger.info('Processing started', { step: 'validation' });
  logger.warn('Rate limit warning', { currentRate: 95 });
  logger.error('Processing failed', new Error('Something went wrong'));

  // You can still override request context for specific logs if needed
  logger.info('Custom log', {}, { customContext: 'value' });

  // The resulting log will include:
  // {
  //   "message": "Request received",
  //   "lambda": {
  //     "functionName": "my-lambda-function",
  //     "functionVersion": "$LATEST",
  //     "invokedFunctionArn": "arn:aws:lambda:us-east-1:123456789:function:my-lambda-function",
  //     "memoryLimitInMB": 512,
  //     "awsRequestId": "abc-123-def-456",
  //     "logGroupName": "/aws/lambda/my-lambda-function",
  //     "logStreamName": "2025/01/15/[$LATEST]abc123",
  //     "remainingTimeInMillis": 30000
  //   },
  //   ...
  // }
};
```

### Using Bound Logger (Cleaner API)

```javascript
const Logger = require('@silicon/logger');

const logger = new Logger({
  endpoint: process.env.SPLUNK_LAMBDA_ARN,
  environment: 'dev',
  source: 'My Service'
});

// Create a bound logger with default request context
const boundLogger = logger.createBoundLogger(
  { requestId: 'req-123', userId: 'user-456' },
  ['data.password', 'data.privateKey'] // Default sensitive paths
);

// Now you can log without passing request context every time
boundLogger.info('User action', { action: 'login' });
boundLogger.warn('Suspicious activity', { ip: '1.2.3.4' });
```

### Custom IP Extraction

```javascript
const Logger = require('@silicon/logger');

const logger = new Logger({
  endpoint: process.env.SPLUNK_LAMBDA_ARN,
  getClientIp: (requestContext) => {
    // Custom IP extraction logic
    return requestContext.headers?.['x-custom-ip'] || 
           requestContext.ip || 
           null;
  }
});

logger.info('Request received', {}, { 
  headers: { 'x-custom-ip': '192.168.1.1' } 
});
```

### Masking Sensitive Data

```javascript
const logger = new Logger({
  endpoint: process.env.SPLUNK_LAMBDA_ARN
});

// Mask specific paths in log data
logger.info('User data', 
  { 
    user: { 
      email: 'user@example.com',
      password: 'secret123',
      data: {
        privateKey: 'key123'
      }
    }
  },
  null, // requestContext
  ['user.password', 'user.data.privateKey'] // paths to mask
);

// The password and privateKey will be masked as '***MASKED***'
```

### Error Logging

```javascript
try {
  // ... some code that might throw ...
  throw new Error('Something went wrong');
} catch (error) {
  // Error objects are automatically formatted
  logger.error('Operation failed', error, requestContext);
  
  // Or pass error details manually
  logger.error('Operation failed', {
    errorName: error.name,
    errorMessage: error.message,
    errorStack: error.stack
  }, requestContext);
}
```

## Log Format

Logs are structured in a Splunk-optimized format with the following top-level fields:

```json
{
  "_time": "2025-01-15T10:30:00.000Z",
  "host": "my-function",
  "source": "My Application",
  "sourcetype": "json",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "level": "INFO",
  "message": "User logged in",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "environment": "prod",
  "apiVersion": "v1",
  "requestId": "req-123",
  "sequence": 1,
  "functionName": "my-function",
  "httpMethod": "GET",
  "httpPath": "/api/users",
  "userId": "user-456",
  "ip": "192.168.1.1",
  "geolocationCity": "New York",
  "geolocationCountry": "United States",
  "jwt": { /* JWT metadata if available */ },
  "queryStringParameters": { /* query params */ },
  "pathParameters": { /* path params */ },
  "log_data": { /* supplemental data passed to logger */ },
  "request": { /* full request context */ },
  "tags": ["level:info", "api:v1"]
}
```

## API Reference

### Methods

#### `logger.info(message, logData, requestContext, pathsToMask)`
Log an info message.

#### `logger.warn(message, logData, requestContext, pathsToMask)`
Log a warning message.

#### `logger.error(message, logData, requestContext, pathsToMask)`
Log an error message. Accepts Error objects or plain objects.

#### `logger.debug(message, logData, requestContext, pathsToMask)`
Log a debug message.

#### `logger.setRequestMetadata(requestId, metadata)`
Set request metadata (IP, geolocation, etc.) for a request. Should be called before logging to ensure metadata is available.

#### `logger.cleanupRequest(requestId)`
Clean up request metadata after request completes.

#### `logger.logRequest(request, context, getGeolocation)`
Log the initial request. Handles both Lambda events and Express request objects.

- **`request`**: Lambda event object, Express request object, or `{ event, context }` format
- **`context`**: Lambda context object (optional, only used if request is a Lambda event)
- **`getGeolocation`**: Optional async function to get geolocation from IP: `(ip, requestContext) => Promise<object>`

**Example - Lambda:**
```javascript
exports.handler = async (event, context) => {
  const logger = new Logger({ endpoint: '...', event, context });
  await logger.logRequest(event, context);
  // ... rest of handler
};
```

**Example - Express:**
```javascript
app.use(async (req, res, next) => {
  const logger = new Logger({ endpoint: '...' });
  await logger.logRequest(req);
  next();
});
```

#### `logger.logResponse(request, context, statusCode, responseBody)`
Log the response. Handles both Lambda events and Express request objects.

- **`request`**: Lambda event object, Express request object, or `{ event, context }` format
- **`context`**: Lambda context object (optional, only used if request is a Lambda event)
- **`statusCode`**: HTTP status code (e.g., 200, 404, 500)
- **`responseBody`**: Response body to log (will be masked appropriately)

**Example - Lambda:**
```javascript
exports.handler = async (event, context) => {
  const logger = new Logger({ endpoint: '...', event, context });
  await logger.logRequest(event, context);
  
  const result = { data: { message: 'Success' } };
  await logger.logResponse(event, context, 200, result);
  return { statusCode: 200, body: JSON.stringify(result) };
};
```

**Example - Express:**
```javascript
app.use(async (req, res, next) => {
  const logger = new Logger({ endpoint: '...' });
  await logger.logRequest(req);
  
  const originalSend = res.send;
  res.send = function(body) {
    logger.logResponse(req, null, res.statusCode, body);
    return originalSend.call(this, body);
  };
  
  next();
});
```

#### `logger.createBoundLogger(requestContext, defaultSensitivePaths)`
Create a bound logger instance with default request context and sensitive paths. Returns a logger object with the same methods but without needing to pass request context each time.

### Utility Methods

#### `logger.maskSensitiveDataInObject(obj)`
Recursively mask sensitive data in an object (passwords, tokens, emails, wallet addresses).

#### `logger.sensitivePaths(obj, paths)`
Mask values at specific paths in an object using dot notation (e.g., `['data.password', 'user.email']`).

## Features

- ✅ **Environment-agnostic**: Works in Lambda, Node.js, Express, and other environments
- ✅ **Structured logging**: Optimized format for Splunk list view
- ✅ **Automatic masking**: Sensitive data (passwords, tokens, emails, wallet addresses) is automatically masked
- ✅ **Request context**: Optional request context support for HTTP requests, Lambda events, etc.
- ✅ **IP and geolocation**: Optional IP extraction and geolocation support
- ✅ **JWT support**: Automatic JWT token extraction and decoding from Authorization headers
- ✅ **Path-based masking**: Mask specific fields using dot notation paths
- ✅ **Fire-and-forget**: Non-blocking log sending to Splunk
- ✅ **Error handling**: Graceful degradation if Splunk is unavailable

## License

ISC

# silicon-logger
