/**
 * @silicon/logger - Robust logging utilities for sending structured logs to Splunk
 * Environment-agnostic logging module that works in Lambda, Node.js, and other environments
 */

const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Try to load AWS SDK v3 for Lambda (optional - will gracefully degrade if not available)
let LambdaClient, InvokeCommand;
try {
  const lambdaSdk = require('@aws-sdk/client-lambda');
  LambdaClient = lambdaSdk.LambdaClient;
  InvokeCommand = lambdaSdk.InvokeCommand;
} catch (error) {
  // AWS SDK v3 not available - Splunk direct logging will be disabled
  LambdaClient = null;
  InvokeCommand = null;
}

// Try to load AWS SDK v3 for SSM (optional - will gracefully degrade if not available)
let SSMClient, GetParameterCommand;
try {
  const ssmSdk = require('@aws-sdk/client-ssm');
  SSMClient = ssmSdk.SSMClient;
  GetParameterCommand = ssmSdk.GetParameterCommand;
} catch (error) {
  // AWS SDK v3 SSM not available - SSM parameter retrieval will be disabled
  SSMClient = null;
  GetParameterCommand = null;
}

/**
 * Logger class for structured logging to Splunk
 * @example
 * // With explicit endpoint
 * const logger = new Logger({
 *   endpoint: 'arn:aws:lambda:us-east-1:123456789:function:splunk-intake',
 *   apiKey: 'your-api-key',
 *   environment: 'dev',
 *   source: 'My Application'
 * });
 * 
 * // With AWS credentials - ARN will be retrieved from SSM
 * const logger = new Logger({
 *   accessKeyId: 'your-access-key',
 *   secretAccessKey: 'your-secret-key',
 *   environment: 'dev',
 *   source: 'My Application'
 * });
 * 
 * logger.info('User logged in', { userId: '123' });
 */
class Logger {
  /**
   * Create a new Logger instance
   * @param {object} config - Logger configuration
   * @param {string} [config.endpoint] - Splunk Lambda ARN (e.g., "arn:aws:lambda:...") or HTTP POST URL (e.g., "https://..."). If not provided and AWS credentials are available, will retrieve from SSM Parameter Store.
   * @param {string} [config.accessKeyId] - AWS access key ID (for Lambda ARN, optional, can use env var AWS_ACCESS_KEY_ID)
   * @param {string} [config.secretAccessKey] - AWS secret access key (for Lambda ARN, optional, can use env var AWS_SECRET_ACCESS_KEY)
   * @param {string} [config.apiKey] - For Lambda: "accessKeyId:secretAccessKey" format. For HTTP URL: x-api-key header value
   * @param {string} [config.xApiKey] - x-api-key header value for HTTP POST endpoints (alternative to apiKey for URLs)
   * @param {string} [config.environment] - Environment name (e.g., 'dev', 'prod')
   * @param {string} [config.source] - Source system identifier (default: 'Silicon Logger')
   * @param {string} [config.region] - AWS region (for Lambda ARN, default: 'us-east-1' or AWS_REGION env var)
   * @param {object} [config.event] - Lambda event object (optional, used for all logs in this instance)
   * @param {object} [config.context] - Lambda context object (optional, used for all logs in this instance)
   * @param {function} [config.getClientIp] - Custom function to extract client IP from request context
   * @param {function} [config.getGeolocation] - Custom function to get geolocation from IP
   */
  constructor(config) {
    if (!config) {
      throw new Error('Logger requires a config object');
    }

    this.environment = config.environment || process.env.ENV || 'unknown';
    this.source = config.source || 'Silicon Logger';
    this.region = config.region || process.env.AWS_REGION || 'us-east-1';
    this.getClientIp = config.getClientIp || null;
    this.getGeolocation = config.getGeolocation || null;

    // Store Lambda event and context for use in all logs
    this.defaultEvent = config.event || null;
    this.defaultContext = config.context || null;

    // AWS credentials - from constructor, apiKey, or environment variables
    let accessKeyId = null;
    let secretAccessKey = null;
    
    if (config.apiKey) {
      // Parse apiKey in format "accessKeyId:secretAccessKey"
      const parts = config.apiKey.split(':');
      if (parts.length === 2) {
        accessKeyId = parts[0];
        secretAccessKey = parts[1];
      } else {
        // Single value - treat as access key ID only
        accessKeyId = config.apiKey;
        secretAccessKey = config.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY || null;
      }
    } else {
      accessKeyId = config.accessKeyId || process.env.AWS_ACCESS_KEY_ID || null;
      secretAccessKey = config.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY || null;
    }

    // Check if we have AWS credentials
    const hasAwsCredentials = accessKeyId || secretAccessKey || 
                              process.env.AWS_ACCESS_KEY_ID || 
                              process.env.AWS_SECRET_ACCESS_KEY ||
                              process.env.AWS_SESSION_TOKEN; // Support IAM roles with session tokens

    // Set endpoint - either provided, or will be retrieved from SSM if AWS credentials are available
    this.endpoint = config.endpoint || null;
    this.hasEndpoint = !!this.endpoint;

    // If endpoint is not provided, we'll try to retrieve from SSM if AWS credentials are available
    if (!this.endpoint && hasAwsCredentials) {
      // Endpoint will be retrieved lazily from SSM when needed
      this.endpointPromise = null;
      this.endpointResolved = false;
    } else if (!this.endpoint) {
      throw new Error('Logger requires either an endpoint (Splunk Lambda ARN or HTTP POST URL) or AWS credentials to retrieve from SSM Parameter Store');
    } else {
      this.endpointPromise = null;
      this.endpointResolved = true;
    }

    // Detect if endpoint is an ARN or URL (will be determined after endpoint is resolved)
    this.isLambdaArn = false;
    this.isHttpUrl = false;

    // Store AWS credentials
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;

    // For HTTP URLs, use x-api-key
    this.xApiKey = null;
    if (this.endpoint && (this.endpoint.startsWith('http://') || this.endpoint.startsWith('https://'))) {
      this.isHttpUrl = true;
      this.xApiKey = config.xApiKey || config.apiKey || process.env.X_API_KEY || null;
      if (!this.xApiKey) {
        throw new Error('HTTP endpoint requires x-api-key (provide via xApiKey, apiKey config, or X_API_KEY env var)');
      }
      // Clear AWS credentials for HTTP mode
      this.accessKeyId = null;
      this.secretAccessKey = null;
    } else if (this.endpoint && this.endpoint.startsWith('arn:aws:lambda:')) {
      this.isLambdaArn = true;
    } else if (this.endpoint) {
      throw new Error('Endpoint must be either a Lambda ARN (arn:aws:lambda:...) or an HTTP URL (http://... or https://...)');
    }

    // Request-scoped sensitive paths storage
    this.sensitivePathsStore = new Map();

    // Request-scoped metadata storage (IP, geolocation, etc.)
    this.requestMetadataStore = new Map();

    // Splunk Lambda client and configuration (lazy-loaded, only for Lambda ARN)
    this.splunkLambdaClient = null;
    this.splunkLambdaClientPromise = null;

    // SSM client for retrieving Lambda ARN (lazy-loaded)
    this.ssmClient = null;
    this.ssmClientPromise = null;
  }

  /**
   * Decode base64url string (JWT uses base64url encoding, not standard base64)
   * @param {string} str - Base64url encoded string
   * @returns {string} Decoded string
   */
  base64UrlDecode(str) {
    // Convert base64url to base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    while (base64.length % 4) {
      base64 += '=';
    }
    
    // Decode base64
    try {
      return Buffer.from(base64, 'base64').toString('utf8');
    } catch (error) {
      return null;
    }
  }

  /**
   * Mask email addresses in a value (recursively processes objects and arrays)
   * @param {any} value - Value to mask (can be string, object, array, etc.)
   * @returns {any} Masked value
   */
  maskEmailAddresses(value) {
    if (typeof value === 'string' && value.includes('@')) {
      // Mask email: keep first 2 chars and domain, mask the rest
      const parts = value.split('@');
      if (parts.length === 2) {
        const local = parts[0];
        const domain = parts[1];
        const maskedLocal = local.length > 2 
          ? local.substring(0, 2) + '*'.repeat(Math.min(local.length - 2, 6))
          : '*'.repeat(Math.min(local.length, 3));
        return `${maskedLocal}@${domain}`;
      }
      return value; // Not a valid email format, return as-is
    }
    
    if (Array.isArray(value)) {
      return value.map(item => this.maskEmailAddresses(item));
    }
    
    if (value && typeof value === 'object') {
      const masked = {};
      for (const [key, val] of Object.entries(value)) {
        masked[key] = this.maskEmailAddresses(val);
      }
      return masked;
    }
    
    return value;
  }

  /**
   * Extract and decode JWT token from headers or request context
   * @param {object} requestContext - Request context object (can be { event, context }, event, headers, etc.)
   * @returns {object|null} Decoded JWT payload with masked emails, or null if no token found
   */
  extractJwtMetadata(requestContext) {
    if (!requestContext) {
      return null;
    }

    // Handle event/context format: { event, context }
    let headers = null;
    if (requestContext.event && requestContext.context) {
      headers = requestContext.event.headers;
    } else if (requestContext.headers) {
      // Direct event object or headers object
      headers = requestContext.headers;
    } else if (typeof requestContext === 'object') {
      // Try as direct headers object
      headers = requestContext;
    }
    
    if (!headers || typeof headers !== 'object') {
      return null;
    }

    // Get Authorization header (case-insensitive)
    const authHeader = headers['Authorization'] || 
                        headers['authorization'] || 
                        headers['AUTHORIZATION'];
    
    if (!authHeader) {
      return null;
    }
    
    // Extract token (handle "Bearer <token>" format)
    const tokenMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    const token = tokenMatch ? tokenMatch[1] : authHeader;
    
    if (!token) {
      return null;
    }
    
    try {
      // JWT format: header.payload.signature
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null; // Invalid JWT format
      }
      
      // Decode payload (second part)
      const payloadJson = this.base64UrlDecode(parts[1]);
      if (!payloadJson) {
        return null;
      }
      
      const payload = JSON.parse(payloadJson);
      
      // Mask all sensitive data in the payload recursively (emails, wallet addresses, tokens, etc.)
      const maskedPayload = this.maskSensitiveDataInObject(payload);
      
      return maskedPayload;
    } catch (error) {
      // If decoding fails, return null (don't log errors for invalid tokens)
      return null;
    }
  }

  /**
   * Extract request ID from request context
   * Supports multiple formats: event/context objects, headers, requestContext, or direct value
   * @param {object} requestContext - Request context object (optional, can be { event, context }, event, or headers)
   * @returns {string|null} Request ID if found
   */
  extractRequestId(requestContext) {
    if (!requestContext) {
      return null;
    }

    // Handle event/context format: { event, context }
    if (requestContext.event && requestContext.context) {
      const event = requestContext.event;
      const context = requestContext.context;
      
      // Try headers first
      if (event?.headers) {
        const requestId = event.headers['X-Request-Id'] || event.headers['x-request-id'];
        if (requestId) return requestId;
      }
      
      // Fallback to requestContext.requestId
      if (event?.requestContext?.requestId) {
        return event.requestContext.requestId;
      }
      
      // Fallback to Lambda context awsRequestId
      if (context?.awsRequestId) {
        return context.awsRequestId;
      }
      
      return null;
    }

    // Handle direct event object (API Gateway event)
    if (requestContext.headers || requestContext.requestContext) {
      // Try headers first
      if (requestContext.headers) {
        const requestId = requestContext.headers['X-Request-Id'] || requestContext.headers['x-request-id'];
        if (requestId) return requestId;
      }
      
      // Fallback to requestContext.requestId
      if (requestContext.requestContext?.requestId) {
        return requestContext.requestContext.requestId;
      }
    }

    // Try to get requestId from headers (generic format)
    const headers = requestContext.headers || requestContext;
    if (headers && typeof headers === 'object') {
      const requestId = headers['X-Request-Id'] || headers['x-request-id'];
      if (requestId) return requestId;
    }
    
    // Fallback to requestContext.requestId
    if (requestContext.requestId) {
      return requestContext.requestId;
    }
    
    // Fallback to awsRequestId (Lambda context)
    if (requestContext.awsRequestId) {
      return requestContext.awsRequestId;
    }
    
    return null;
  }

  /**
   * Extract API Gateway request context
   * @param {object} event - API Gateway event object
   * @returns {object} Request context metadata
   */
  extractRequestContext(event) {
    if (!event) return {};
    
    const requestContext = event.requestContext || {};
    
    const context = {
      queryStringParameters: event.queryStringParameters !== undefined ? event.queryStringParameters : null,
      pathParameters: event.pathParameters !== undefined ? event.pathParameters : null,
      path: event.path || null,
      httpMethod: event.httpMethod || event.requestContext?.httpMethod || null,
    };
    
    if (event.requestContext) {
      context.requestId = requestContext.requestId || null;
      context.apiId = requestContext.apiId || null;
      context.stage = requestContext.stage || null;
      context.resourcePath = requestContext.resourcePath || null;
      context.accountId = requestContext.accountId || null;
      context.userAgent = event.headers?.['User-Agent'] || event.headers?.['user-agent'] || null;
      context.sourceIp = requestContext.identity?.sourceIp || requestContext.identity?.sourceIp || null;
      context.userArn = requestContext.identity?.userArn || null;
      context.user = requestContext.identity?.user || null;
    }
    
    if (event.headers) {
      context.origin = event.headers['Origin'] || event.headers['origin'] || null;
      context.referer = event.headers['Referer'] || event.headers['referer'] || null;
      context.contentType = event.headers['Content-Type'] || event.headers['content-type'] || null;
      context.accept = event.headers['Accept'] || event.headers['accept'] || null;
      context.acceptLanguage = event.headers['Accept-Language'] || event.headers['accept-language'] || null;
      context.acceptEncoding = event.headers['Accept-Encoding'] || event.headers['accept-encoding'] || null;
      context.xForwardedFor = event.headers['X-Forwarded-For'] || event.headers['x-forwarded-for'] || null;
      context.xRealIp = event.headers['X-Real-IP'] || event.headers['x-real-ip'] || null;
      context.xForwardedProto = event.headers['X-Forwarded-Proto'] || event.headers['x-forwarded-proto'] || null;
      context.xForwardedPort = event.headers['X-Forwarded-Port'] || event.headers['x-forwarded-port'] || null;
      context.xAmznTraceId = event.headers['X-Amzn-Trace-Id'] || event.headers['x-amzn-trace-id'] || null;
      context.cfRay = event.headers['CF-Ray'] || event.headers['cf-ray'] || null;
      context.cfConnectingIp = event.headers['CF-Connecting-IP'] || event.headers['cf-connecting-ip'] || null;
      context.cfCountry = event.headers['CF-IPCountry'] || event.headers['cf-ipcountry'] || null;
      context.cfVisitor = event.headers['CF-Visitor'] || event.headers['cf-visitor'] || null;
    }
    
    return context;
  }

  /**
   * Extract Lambda context information
   * @param {object} context - Lambda context object
   * @returns {object} Lambda context metadata
   */
  extractLambdaContext(context) {
    if (!context) return {};
    
    return {
      functionName: context.functionName || null,
      functionVersion: context.functionVersion || null,
      invokedFunctionArn: context.invokedFunctionArn || null,
      memoryLimitInMB: context.memoryLimitInMB || null,
      awsRequestId: context.awsRequestId || null,
      logGroupName: context.logGroupName || null,
      logStreamName: context.logStreamName || null,
      remainingTimeInMillis: context.getRemainingTimeInMillis ? context.getRemainingTimeInMillis() : null,
    };
  }

  /**
   * Extract client IP from request context
   * Uses custom getClientIp function if provided, otherwise tries common patterns
   * @param {object} requestContext - Request context object (can be { event, context }, event, or headers)
   * @returns {string|null} Client IP address or null if not found
   */
  extractClientIp(requestContext) {
    if (!requestContext) {
      return null;
    }

    // Handle event/context format: { event, context }
    let event = null;
    if (requestContext.event && requestContext.context) {
      event = requestContext.event;
    } else if (requestContext.headers || requestContext.requestContext) {
      // Direct event object
      event = requestContext;
    }

    // Use custom IP extraction function if provided
    if (this.getClientIp && typeof this.getClientIp === 'function') {
      try {
        return this.getClientIp(event || requestContext);
      } catch (error) {
        // Fall through to default extraction
      }
    }

    // Default extraction logic
    if (event) {
      const headers = event.headers;
      if (headers && typeof headers === 'object') {
        // Check X-Forwarded-For header (first IP in the chain is the original client)
        const xForwardedFor = headers['X-Forwarded-For'] || 
                              headers['x-forwarded-for'] ||
                              headers['X-FORWARDED-FOR'];
        if (xForwardedFor) {
          const firstIp = xForwardedFor.split(',')[0].trim();
          if (firstIp) {
            return firstIp;
          }
        }

        // Check X-Real-IP header
        const xRealIp = headers['X-Real-IP'] || 
                        headers['x-real-ip'] ||
                        headers['X-REAL-IP'];
        if (xRealIp) {
          return xRealIp.trim();
        }
      }

      // Fallback to requestContext.identity.sourceIp (API Gateway format)
      if (event.requestContext?.identity?.sourceIp) {
        return event.requestContext.identity.sourceIp;
      }
    }

    // Fallback for generic requestContext format
    const headers = requestContext.headers || requestContext;
    if (headers && typeof headers === 'object') {
      const xForwardedFor = headers['X-Forwarded-For'] || 
                            headers['x-forwarded-for'] ||
                            headers['X-FORWARDED-FOR'];
      if (xForwardedFor) {
        const firstIp = xForwardedFor.split(',')[0].trim();
        if (firstIp) {
          return firstIp;
        }
      }

      const xRealIp = headers['X-Real-IP'] || 
                      headers['x-real-ip'] ||
                      headers['X-REAL-IP'];
      if (xRealIp) {
        return xRealIp.trim();
      }
    }

    if (requestContext.requestContext?.identity?.sourceIp) {
      return requestContext.requestContext.identity.sourceIp;
    }

    if (requestContext.identity?.sourceIp) {
      return requestContext.identity.sourceIp;
    }

    return null;
  }

  /**
   * Mask wallet addresses in a specific format
   * Ethereum: 0x01d0b4db0dbaf30899ad57a170c48f491e5a879f -> 0x01d***********1e5a879f
   * Chia: xch1222...dfdfd -> xch1222*****dfdfd
   * @param {string} address - Wallet address to mask
   * @returns {string} Masked wallet address
   */
  maskWalletAddress(address) {
    if (!address || typeof address !== 'string') {
      return address;
    }
    
    // Ethereum address: 0x followed by 40 hex characters (42 total)
    if (address.startsWith('0x') && /^0x[a-fA-F0-9]{40}$/.test(address)) {
      // Format: 0x01d***********1e5a879f (first 5 chars, asterisks, last 9 chars)
      if (address.length >= 14) {
        return `${address.substring(0, 5)}${'*'.repeat(address.length - 14)}${address.substring(address.length - 9)}`;
      }
      return '***MASKED***';
    }
    
    // Chia address: xch followed by various formats
    if (address.startsWith('xch') && address.length > 10) {
      // Format: xch1222*****dfdfd (first 7 chars, asterisks, last 5 chars)
      if (address.length >= 12) {
        return `${address.substring(0, 7)}${'*'.repeat(address.length - 12)}${address.substring(address.length - 5)}`;
      }
      // If too short, use simpler format
      if (address.length >= 8) {
        return `${address.substring(0, 4)}${'*'.repeat(address.length - 7)}${address.substring(address.length - 3)}`;
      }
      return '***MASKED***';
    }
    
    return address; // Not a recognized wallet address format
  }

  /**
   * Mask sensitive data in objects (recursively)
   * @param {any} obj - Object to mask
   * @returns {any} Masked object
   */
  maskSensitiveDataInObject(obj) {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.maskSensitiveDataInObject(item));
    }
    
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization', 'apiKey', 'apikey', 'email'];
    const masked = {};
    
    for (const [key, value] of Object.entries(obj)) {
      const keyLower = key.toLowerCase();
      const isSensitive = sensitiveFields.some(field => keyLower.includes(field));
      
      if (isSensitive && typeof value === 'string' && value.length > 0) {
        masked[key] = '***MASKED***';
      } else if (typeof value === 'string') {
        // Check for wallet addresses
        if ((value.startsWith('0x') || value.startsWith('xch')) && value.length > 10) {
          masked[key] = this.maskWalletAddress(value);
        } else if (value.includes('@')) {
          // Check for email addresses
          masked[key] = this.maskEmailAddresses(value);
        } else {
          masked[key] = value;
        }
      } else if (typeof value === 'object' && value !== null) {
        masked[key] = this.maskSensitiveDataInObject(value);
      } else {
        masked[key] = value;
      }
    }
    
    return masked;
  }

  /**
   * Mask values at specific paths in an object using dot notation
   * Supports array notation like 'data.private_keys[3].value'
   * @param {any} obj - Object to mask
   * @param {string[]} paths - Array of dot-separated paths
   * @returns {any} Object with values at specified paths masked
   */
  sensitivePaths(obj, paths = []) {
    if (!obj || typeof obj !== 'object' || !Array.isArray(paths) || paths.length === 0) {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.sensitivePaths(item, paths));
    }
    
    // Create a deep copy to avoid mutating the original
    const masked = JSON.parse(JSON.stringify(obj));
    
    for (const path of paths) {
      if (!path || typeof path !== 'string') continue;
      
      const pathParts = path.split('.');
      let current = masked;
      
      // Navigate to the parent of the target value
      for (let i = 0; i < pathParts.length - 1; i++) {
        const part = pathParts[i];
        
        // Handle array indices like 'private_keys[3]'
        const arrayMatch = part.match(/^(.+)\[(\d+)\]$/);
        if (arrayMatch) {
          const arrayKey = arrayMatch[1];
          const arrayIndex = parseInt(arrayMatch[2], 10);
          
          if (current[arrayKey] && Array.isArray(current[arrayKey]) && current[arrayKey][arrayIndex] !== undefined) {
            current = current[arrayKey][arrayIndex];
          } else {
            current = null;
            break;
          }
        } else {
          if (current[part] && typeof current[part] === 'object' && current[part] !== null) {
            current = current[part];
          } else {
            current = null;
            break;
          }
        }
      }
      
      // Mask the value at the final path
      if (current !== null && current !== undefined) {
        const finalKey = pathParts[pathParts.length - 1];
        const arrayMatch = finalKey.match(/^(.+)\[(\d+)\]$/);
        
        if (arrayMatch) {
          // Array index in final key
          const arrayKey = arrayMatch[1];
          const arrayIndex = parseInt(arrayMatch[2], 10);
          if (current[arrayKey] && Array.isArray(current[arrayKey]) && current[arrayKey][arrayIndex] !== undefined) {
            current[arrayKey][arrayIndex] = '***MASKED***';
          }
        } else {
          // Regular key
          if (current[finalKey] !== undefined) {
            current[finalKey] = '***MASKED***';
          }
        }
      }
    }
    
    return masked;
  }

  /**
   * Build structured log entry optimized for Splunk
   * @param {string} level - Log level (info, warn, error, debug)
   * @param {string} message - Log message
   * @param {object} logData - Log data to include (optional)
   * @param {object} requestContext - Request context (optional, can be event, headers, etc.)
   * @param {string[]} pathsToMask - Array of dot-separated paths to mask (optional)
   * @returns {object} Structured log entry
   */
  buildLogEntry(level, message, logData = null, requestContext = null, pathsToMask = []) {
    // Merge default event/context with provided requestContext
    // If requestContext is provided, use it; otherwise use default event/context
    let mergedRequestContext = requestContext;
    let event = null;
    let context = null;
    
    if (!mergedRequestContext && (this.defaultEvent || this.defaultContext)) {
      // Build request context from default event and context
      event = this.defaultEvent;
      context = this.defaultContext;
      if (event || context) {
        mergedRequestContext = {};
        if (event) {
          mergedRequestContext.event = event;
        }
        if (context) {
          mergedRequestContext.context = context;
        }
      }
    } else if (mergedRequestContext) {
      // Extract event and context from requestContext
      if (mergedRequestContext.event && mergedRequestContext.context) {
        // Already in { event, context } format
        event = mergedRequestContext.event;
        context = mergedRequestContext.context;
      } else if (mergedRequestContext.headers || mergedRequestContext.requestContext) {
        // Direct event object
        event = mergedRequestContext;
        // Try to get context from default or nested
        context = mergedRequestContext.context || this.defaultContext;
      } else {
        // Generic requestContext, try to merge with defaults
        event = this.defaultEvent || (mergedRequestContext.event ? mergedRequestContext.event : null);
        context = this.defaultContext || (mergedRequestContext.context ? mergedRequestContext.context : null);
        if (event || context) {
          mergedRequestContext = {};
          if (event) mergedRequestContext.event = event;
          if (context) mergedRequestContext.context = context;
        }
      }
    }
    
    // Extract request ID (handles event/context format automatically)
    const requestId = this.extractRequestId(mergedRequestContext) || crypto.randomUUID();
    
    // Extract JWT metadata if Authorization header is present
    const jwtMetadata = this.extractJwtMetadata(mergedRequestContext);
    
    // Get IP address and geolocation from request metadata store or extract from context
    let clientIp = null;
    let geolocation = null;
    
    // Try to get from request metadata store (set by setRequestMetadata)
    const requestMetadata = this.requestMetadataStore.get(requestId);
    if (requestMetadata) {
      clientIp = requestMetadata.ip;
      geolocation = requestMetadata.geolocation;
    }
    
    // If not in store, try to extract IP from context
    if (!clientIp && mergedRequestContext) {
      clientIp = this.extractClientIp(mergedRequestContext);
    }
    
    // Get geolocation if IP is available and getGeolocation function is provided
    if (clientIp && !geolocation && this.getGeolocation && typeof this.getGeolocation === 'function') {
      try {
        // Note: This is synchronous in the current implementation
        // For async geolocation, use setRequestMetadata before logging
        geolocation = this.getGeolocation(clientIp, mergedRequestContext);
      } catch (error) {
        // Silently fail - geolocation is optional
      }
    }
    
    // Extract API version from path if available (e.g., /v1/example -> v1)
    let apiVersion = null;
    if (event) {
      const path = event.path || event.requestContext?.path || null;
      if (path && typeof path === 'string') {
        const match = path.match(/^\/(v\d+)\//);
        if (match) {
          apiVersion = match[1];
        }
      }
    } else if (mergedRequestContext) {
      const path = mergedRequestContext.path || mergedRequestContext.requestContext?.path || null;
      if (path && typeof path === 'string') {
        const match = path.match(/^\/(v\d+)\//);
        if (match) {
          apiVersion = match[1];
        }
      }
    }
    
    // Mask sensitive data in logData
    let maskedLogData = null;
    if (logData !== null && logData !== undefined) {
      let processedLogData = this.maskSensitiveDataInObject(logData);
      if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0) {
        processedLogData = this.sensitivePaths(processedLogData, pathsToMask);
      }
      maskedLogData = processedLogData;
      if (maskedLogData === null || maskedLogData === undefined) {
        maskedLogData = null;
      } else if (typeof maskedLogData !== 'object' || Array.isArray(maskedLogData)) {
        maskedLogData = { value: maskedLogData };
      }
    }
    
    // Extract function/service name from context
    // Support both direct Lambda context and nested context in event
    const lambdaContextForName = context || mergedRequestContext?.context || mergedRequestContext;
    const functionName = lambdaContextForName?.functionName || null;
    const functionNameFull = functionName;
    const functionNameShort = functionNameFull
      ? functionNameFull.replace(/^silicon-api-/, '').replace(/-dev$|-prod$|-staging$|-v\d+$/, '')
      : null;
    
    // Extract HTTP method and path
    const httpMethod = event?.httpMethod || 
                      event?.requestContext?.httpMethod ||
                      mergedRequestContext?.httpMethod || 
                      mergedRequestContext?.requestContext?.httpMethod || 
                      mergedRequestContext?.method ||
                      null;
    const httpPath = event?.path || 
                    event?.requestContext?.path ||
                    mergedRequestContext?.path || 
                    mergedRequestContext?.requestContext?.path ||
                    mergedRequestContext?.url ||
                    null;
    
    // Extract user ID from JWT
    const userId = jwtMetadata?.sub || null;
    
    // Extract geolocation fields
    const geoCity = geolocation?.city || null;
    const geoCountry = geolocation?.country || null;
    
    // Extract X-Request-Comment header if present (case-insensitive)
    let requestComment = null;
    if (event?.headers) {
      requestComment = event.headers['X-Request-Comment'] || 
                      event.headers['x-request-comment'] || 
                      event.headers['X-REQUEST-COMMENT'] ||
                      null;
    } else if (mergedRequestContext) {
      const headers = mergedRequestContext.headers || mergedRequestContext;
      if (headers && typeof headers === 'object') {
        requestComment = headers['X-Request-Comment'] || 
                        headers['x-request-comment'] || 
                        headers['X-REQUEST-COMMENT'] ||
                        null;
      }
    }
    
    // Build log entry optimized for Splunk list view
    const logEntry = {
      // Standard Splunk fields
      _time: new Date().toISOString(),
      host: functionNameFull || functionNameShort || 'unknown',
      source: this.source,
      sourcetype: 'json',
      
      // Core identification fields
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message: message,
      id: crypto.randomUUID(),
      
      // Environment and deployment
      environment: this.environment,
      apiVersion: apiVersion || null,
      
      // Request tracking
      requestId: requestId || null,
      
      // Function/service identification
      functionName: functionNameShort || functionNameFull || null,
      functionNameFull: functionNameFull || null,
      
      // HTTP request details
      httpMethod: httpMethod || null,
      httpPath: httpPath || null,
      
      // User identification
      userId: userId || null,
      
      // Network and geolocation
      ip: clientIp || null,
      geolocationCity: geoCity || null,
      geolocationCountry: geoCountry || null,
      
      // Request comment (from X-Request-Comment header)
      requestComment: requestComment || null,
    };
    
    // Add JWT metadata (nested)
    if (jwtMetadata) {
      logEntry.jwt = jwtMetadata;
    }
    
    // Add query and path parameters if available
    if (event) {
      const queryParams = event.queryStringParameters !== undefined ? event.queryStringParameters : null;
      const pathParams = event.pathParameters !== undefined ? event.pathParameters : null;
      
      if (queryParams !== null && queryParams !== undefined) {
        let maskedQueryParams = typeof queryParams === 'object' && queryParams !== null
          ? this.maskSensitiveDataInObject(queryParams)
          : queryParams;
        if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0 && typeof maskedQueryParams === 'object' && maskedQueryParams !== null) {
          maskedQueryParams = this.sensitivePaths(maskedQueryParams, pathsToMask);
        }
        logEntry.queryStringParameters = maskedQueryParams;
      } else {
        logEntry.queryStringParameters = null;
      }
      
      if (pathParams !== null && pathParams !== undefined) {
        let maskedPathParams = typeof pathParams === 'object' && pathParams !== null
          ? this.maskSensitiveDataInObject(pathParams)
          : pathParams;
        if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0 && typeof maskedPathParams === 'object' && maskedPathParams !== null) {
          maskedPathParams = this.sensitivePaths(maskedPathParams, pathsToMask);
        }
        logEntry.pathParameters = maskedPathParams;
      } else {
        logEntry.pathParameters = null;
      }
    } else if (mergedRequestContext) {
      // Fallback for generic requestContext format
      const queryParams = mergedRequestContext.queryStringParameters || 
                         mergedRequestContext.query ||
                         mergedRequestContext.requestContext?.queryStringParameters ||
                         null;
      const pathParams = mergedRequestContext.pathParameters || 
                        mergedRequestContext.params ||
                        mergedRequestContext.requestContext?.pathParameters ||
                        null;
      
      if (queryParams !== null && queryParams !== undefined) {
        let maskedQueryParams = typeof queryParams === 'object' && queryParams !== null
          ? this.maskSensitiveDataInObject(queryParams)
          : queryParams;
        if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0 && typeof maskedQueryParams === 'object' && maskedQueryParams !== null) {
          maskedQueryParams = this.sensitivePaths(maskedQueryParams, pathsToMask);
        }
        logEntry.queryStringParameters = maskedQueryParams;
      } else {
        logEntry.queryStringParameters = null;
      }
      
      if (pathParams !== null && pathParams !== undefined) {
        let maskedPathParams = typeof pathParams === 'object' && pathParams !== null
          ? this.maskSensitiveDataInObject(pathParams)
          : pathParams;
        if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0 && typeof maskedPathParams === 'object' && maskedPathParams !== null) {
          maskedPathParams = this.sensitivePaths(maskedPathParams, pathsToMask);
        }
        logEntry.pathParameters = maskedPathParams;
      } else {
        logEntry.pathParameters = null;
      }
    }
    
    // Add log_data (supplemental information passed to logger)
    if (logData !== null && logData !== undefined) {
      if (maskedLogData !== null && maskedLogData !== undefined && typeof maskedLogData === 'object' && !Array.isArray(maskedLogData)) {
        logEntry.log_data = maskedLogData;
      } else {
        const fallbackMasked = this.maskSensitiveDataInObject(logData);
        if (fallbackMasked && typeof fallbackMasked === 'object' && !Array.isArray(fallbackMasked)) {
          logEntry.log_data = fallbackMasked;
        } else {
          logEntry.log_data = logData;
        }
      }
    }
    
    // Add Lambda context (nested, as it's less frequently searched)
    // Check if context is available from event/context format or mergedRequestContext
    let lambdaContext = null;
    if (context) {
      // Use context from event/context format
      lambdaContext = context;
    } else if (mergedRequestContext) {
      // Check if there's a nested context object (Lambda event format)
      if (mergedRequestContext.context && typeof mergedRequestContext.context === 'object') {
        lambdaContext = mergedRequestContext.context;
      } 
      // Check if mergedRequestContext itself has Lambda context fields
      else if (mergedRequestContext.functionName || mergedRequestContext.awsRequestId || mergedRequestContext.invokedFunctionArn) {
        lambdaContext = mergedRequestContext;
      }
    }
    
    if (lambdaContext) {
      const extractedLambda = this.extractLambdaContext(lambdaContext);
      if (extractedLambda && Object.keys(extractedLambda).length > 0) {
        let maskedLambda = this.maskSensitiveDataInObject(extractedLambda);
        if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0) {
          maskedLambda = this.sensitivePaths(maskedLambda, pathsToMask);
        }
        logEntry.lambda = maskedLambda;
      }
    }
    
    // Add full request context (nested, contains headers and other detailed info)
    // Use extractRequestContext if we have an event object, otherwise use mergedRequestContext
    if (event) {
      const requestContext = this.extractRequestContext(event);
      let maskedRequest = this.maskSensitiveDataInObject(requestContext);
      if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0) {
        maskedRequest = this.sensitivePaths(maskedRequest, pathsToMask);
      }
      logEntry.request = maskedRequest;
    } else if (mergedRequestContext) {
      let maskedRequest = this.maskSensitiveDataInObject(mergedRequestContext);
      if (pathsToMask && Array.isArray(pathsToMask) && pathsToMask.length > 0) {
        maskedRequest = this.sensitivePaths(maskedRequest, pathsToMask);
      }
      logEntry.request = maskedRequest;
    }
    
    // Add custom tags for filtering
    const tags = [];
    if (maskedLogData && maskedLogData.lifecycle) {
      tags.push(`lifecycle:${maskedLogData.lifecycle}`);
    }
    if (level) {
      tags.push(`level:${level.toLowerCase()}`);
    }
    if (apiVersion) {
      tags.push(`api:${apiVersion}`);
    }
    if (tags.length > 0) {
      logEntry.tags = tags;
    }
    
    return logEntry;
  }

  /**
   * Transform log entry to Splunk format
   * @param {object} logEntry - Log entry from buildLogEntry
   * @returns {object} Splunk-formatted log entry
   */
  transformToSplunkFormat(logEntry) {
    const { message, level, environment, ...restOfLogEntry } = logEntry;
    
    return {
      message: message,
      level: level,
      environment: environment,
      metadata: restOfLogEntry,
      source: this.source,
      sourcetype: 'json',
    };
  }

  /**
   * Get SSM client with credentials from constructor or environment variables
   * @returns {Promise<SSMClient|null>} SSM client or null if not available
   */
  async getSSMClient() {
    if (this.ssmClient) {
      return this.ssmClient;
    }

    if (this.ssmClientPromise) {
      return this.ssmClientPromise;
    }

    if (!SSMClient || !GetParameterCommand) {
      return null;
    }

    this.ssmClientPromise = (async () => {
      try {
        // Use credentials from constructor or environment variables
        const accessKeyId = this.accessKeyId;
        const secretAccessKey = this.secretAccessKey;

        // Build client config
        const clientConfig = {
          region: this.region,
        };

        // If explicit credentials are provided, use them
        if (accessKeyId && secretAccessKey) {
          clientConfig.credentials = {
            accessKeyId: accessKeyId,
            secretAccessKey: secretAccessKey,
          };
        }
        // Otherwise, try to use default AWS credentials (from IAM role, ~/.aws/credentials, etc.)

        this.ssmClient = new SSMClient(clientConfig);
        return this.ssmClient;
      } catch (error) {
        console.error('Failed to create SSM client:', error);
        return null;
      }
    })();

    return this.ssmClientPromise;
  }

  /**
   * Retrieve intake Lambda ARN from SSM Parameter Store
   * @returns {Promise<string|null>} Lambda ARN or null if not found
   */
  async getIntakeLambdaArnFromSSM() {
    try {
      const ssmClient = await this.getSSMClient();
      if (!ssmClient) {
        console.error('SSM client not available - cannot retrieve Lambda ARN from SSM');
        return null;
      }

      const parameterName = '/silicon/splunk/intake-lambda-arn';
      const command = new GetParameterCommand({
        Name: parameterName,
      });

      const response = await ssmClient.send(command);
      
      if (response.Parameter && response.Parameter.Value) {
        return response.Parameter.Value;
      }

      return null;
    } catch (error) {
      console.error('Failed to retrieve Lambda ARN from SSM:', error);
      return null;
    }
  }

  /**
   * Ensure endpoint is resolved (either already set or retrieved from SSM)
   * @returns {Promise<string>} Resolved endpoint ARN or URL
   */
  async ensureEndpointResolved() {
    // If endpoint is already set and resolved, return it
    if (this.endpoint && this.endpointResolved) {
      return this.endpoint;
    }

    // If we're already resolving, wait for that promise
    if (this.endpointPromise) {
      return this.endpointPromise;
    }

    // Start resolving from SSM
    this.endpointPromise = (async () => {
      if (!this.endpoint) {
        // Retrieve from SSM
        const arn = await this.getIntakeLambdaArnFromSSM();
        if (!arn) {
          throw new Error('Failed to retrieve intake Lambda ARN from SSM Parameter Store (/silicon/splunk/intake-lambda-arn)');
        }
        this.endpoint = arn;
        
        // Detect if it's a Lambda ARN or HTTP URL
        if (this.endpoint.startsWith('arn:aws:lambda:')) {
          this.isLambdaArn = true;
          this.isHttpUrl = false;
        } else if (this.endpoint.startsWith('http://') || this.endpoint.startsWith('https://')) {
          this.isLambdaArn = false;
          this.isHttpUrl = true;
        } else {
          throw new Error(`Retrieved endpoint from SSM is not a valid Lambda ARN or HTTP URL: ${this.endpoint}`);
        }
      }

      this.endpointResolved = true;
      return this.endpoint;
    })();

    return this.endpointPromise;
  }

  /**
   * Get Splunk Lambda client with credentials from constructor or environment variables
   * @returns {Promise<LambdaClient|null>} Lambda client or null if not available
   */
  async getSplunkLambdaClient() {
    if (this.splunkLambdaClient) {
      return this.splunkLambdaClient;
    }

    if (this.splunkLambdaClientPromise) {
      return this.splunkLambdaClientPromise;
    }

    if (!LambdaClient || !InvokeCommand) {
      return null;
    }

    this.splunkLambdaClientPromise = (async () => {
      try {
        // Use credentials from constructor or environment variables
        const accessKeyId = this.accessKeyId;
        const secretAccessKey = this.secretAccessKey;

        if (!accessKeyId || !secretAccessKey) {
          // Try to use default AWS credentials (from IAM role, ~/.aws/credentials, etc.)
          this.splunkLambdaClient = new LambdaClient({
            region: this.region,
          });
          return this.splunkLambdaClient;
        }

        // Use explicit credentials
        this.splunkLambdaClient = new LambdaClient({
          region: this.region,
          credentials: {
            accessKeyId: accessKeyId,
            secretAccessKey: secretAccessKey,
          },
        });

        return this.splunkLambdaClient;
      } catch (error) {
        console.error('Failed to create Splunk Lambda client:', error);
        return null;
      }
    })();

    return this.splunkLambdaClientPromise;
  }

  /**
   * Send log entry to Splunk endpoint (fire-and-forget, non-blocking)
   * Supports both Lambda ARN (with AWS credentials) and HTTP POST URL (with x-api-key)
   * @param {object} logEntry - Log entry to send
   */
  sendToSplunkLambda(logEntry) {
    // Fire-and-forget - don't block the main execution
    (async () => {
      try {
        // Ensure endpoint is resolved (either already set or retrieved from SSM)
        const endpoint = await this.ensureEndpointResolved();

        // Transform log entry to Splunk format
        const splunkEntry = this.transformToSplunkFormat(logEntry);

        if (this.isHttpUrl) {
          // HTTP POST mode with x-api-key
          await this.sendToHttpEndpoint(splunkEntry);
        } else {
          // Lambda ARN mode with AWS credentials
          const client = await this.getSplunkLambdaClient();
          if (!client) {
            return; // AWS SDK not available or credentials not configured
          }

          // Send as single log (intake function can handle both single and batch)
          const command = new InvokeCommand({
            FunctionName: endpoint,
            InvocationType: 'Event', // Asynchronous invocation (fire-and-forget)
            Payload: JSON.stringify(splunkEntry),
          });

          await client.send(command);
        }
      } catch (error) {
        // Log error but don't break the application if Splunk is down
        console.error('Failed to send log to Splunk endpoint:', error.message);
      }
    })();
  }

  /**
   * Send log entry to HTTP POST endpo int with x-api-key header
   * @param {object} splunkEntry - Transformed log entry
   * @returns {Promise<void>}
   */
  async sendToHttpEndpoint(splunkEntry) {
    return new Promise(async (resolve, reject) => {
      try {
        // Ensure endpoint is resolved
        const endpoint = await this.ensureEndpointResolved();
        const url = new URL(endpoint);
        const isHttps = url.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        const postData = JSON.stringify(splunkEntry);

        const options = {
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
            'x-api-key': this.xApiKey,
          },
        };

        const req = httpModule.request(options, (res) => {
          // Consume response data to free up memory
          res.on('data', () => {});
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve();
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
            }
          });
        });

        req.on('error', (error) => {
          reject(error);
        });

        // Set a timeout to prevent hanging requests
        req.setTimeout(5000, () => {
          req.destroy();
          reject(new Error('Request timeout'));
        });

        req.write(postData);
        req.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Set request metadata (IP, geolocation, etc.) for a request
   * This should be called before logging to ensure IP and geolocation are available
   * @param {string} requestId - Request ID
   * @param {object} metadata - Metadata object with ip, geolocation, etc.
   */
  setRequestMetadata(requestId, metadata) {
    if (requestId) {
      this.requestMetadataStore.set(requestId, metadata);
    }
  }

  /**
   * Clean up request metadata after request completes
   * @param {string} requestId - Request ID to clean up
   */
  cleanupRequest(requestId) {
    if (requestId) {
      // Clean up after a delay to ensure all logs are sent
      setTimeout(() => {
        this.sensitivePathsStore.delete(requestId);
        this.requestMetadataStore.delete(requestId);
      }, 60000); // Clean up after 60 seconds
    }
  }

  /**
   * Normalize request object to a standard format
   * Handles both Lambda event/context and Express request objects
   * @param {object} request - Can be Lambda event, Express req, or { event, context }
   * @param {object} context - Lambda context (optional, only used if request is event)
   * @returns {object} Normalized request object with { event, context } format
   */
  normalizeRequest(request, context = null) {
    if (!request) {
      return { event: null, context: context || this.defaultContext };
    }

    // Already in { event, context } format
    if (request.event && request.context) {
      return { event: request.event, context: request.context };
    }

    // Lambda event object (has headers or requestContext)
    if (request.headers || request.requestContext) {
      return { event: request, context: context || this.defaultContext };
    }

    // Express request object (has method, url, headers, etc.)
    if (request.method && (request.url || request.path)) {
      // Convert Express request to event-like format
      const normalizedEvent = {
        httpMethod: request.method,
        path: request.path || request.url,
        headers: request.headers || {},
        queryStringParameters: request.query || null,
        pathParameters: request.params || null,
        body: request.body || null,
        // Store original Express request for reference
        _expressRequest: request,
      };
      return { event: normalizedEvent, context: context || this.defaultContext };
    }

    // Generic request context
    return { event: request, context: context || this.defaultContext };
  }

  /**
   * Log the initial request (standardized for both Lambda and Express)
   * @param {object} request - Lambda event, Express req, or { event, context }
   * @param {object} context - Lambda context (optional, only used if request is event)
   * @param {function} [getGeolocation] - Optional async function to get geolocation from IP
   * @returns {Promise<void>}
   */
  async logRequest(request, context = null, getGeolocation = null) {
    try {
      // Normalize request to standard format
      const normalized = this.normalizeRequest(request, context);
      const event = normalized.event;
      const contextObj = normalized.context;

      if (!event) {
        return; // No event to log
      }

      const requestId = this.extractRequestId({ event, context: contextObj });
      
      // Parse request body if present
      let requestBody = null;
      if (event.body) {
        if (typeof event.body === 'string') {
          try {
            requestBody = JSON.parse(event.body);
          } catch {
            requestBody = event.body;
          }
        } else {
          requestBody = event.body;
        }
      }
      
      // Extract relevant headers (exclude sensitive ones)
      const relevantHeaders = {};
      if (event.headers) {
        const sensitiveHeaders = ['authorization', 'x-api-key', 'cookie'];
        for (const [key, value] of Object.entries(event.headers)) {
          const lowerKey = key.toLowerCase();
          if (!sensitiveHeaders.includes(lowerKey)) {
            relevantHeaders[key] = value;
          } else {
            relevantHeaders[key] = '[REDACTED]';
          }
        }
      }
      
      // Get client IP address
      const clientIp = this.extractClientIp({ event, context: contextObj });
      
      // Get full geolocation data (async)
      let geolocation = null;
      if (clientIp) {
        if (getGeolocation && typeof getGeolocation === 'function') {
          try {
            geolocation = await getGeolocation(clientIp, { event, context: contextObj });
          } catch (error) {
            // Silently fail - geolocation is optional
          }
        }
      }
      
      // Store IP and geolocation in request-scoped metadata store
      if (requestId) {
        this.setRequestMetadata(requestId, {
          ip: clientIp,
          geolocation: geolocation
        });
      }
      
      // Mask sensitive data in request body
      const maskedBody = requestBody ? this.maskSensitiveDataInObject(requestBody) : null;
      
      // Extract HTTP method and path
      const httpMethod = event.httpMethod || event.method || null;
      const path = event.path || event.url || null;
      
      // Extract query and path parameters
      const queryParams = event.queryStringParameters !== undefined ? event.queryStringParameters : (event.query || null);
      const pathParams = event.pathParameters !== undefined ? event.pathParameters : (event.params || null);
      
      // Log the request
      this.info('Request received', {
        lifecycle: 'request',
        httpMethod: httpMethod,
        path: path,
        pathParameters: pathParams,
        queryStringParameters: queryParams,
        headers: relevantHeaders,
        requestBody: maskedBody,
        ...(clientIp && { ip: clientIp }),
        ...(geolocation && { geolocation }),
      }, { event, context: contextObj });
    } catch (error) {
      console.error('Failed to log request:', error);
    }
  }

  /**
   * Log the response (standardized for both Lambda and Express)
   * @param {object} request - Lambda event, Express req, or { event, context }
   * @param {object} context - Lambda context (optional, only used if request is event)
   * @param {number} statusCode - HTTP status code
   * @param {any} responseBody - Response body to log (will be masked appropriately)
   * @returns {Promise<void>}
   */
  async logResponse(request, context = null, statusCode, responseBody) {
    try {
      // Normalize request to standard format
      const normalized = this.normalizeRequest(request, context);
      const event = normalized.event;
      const contextObj = normalized.context;

      if (!event) {
        return; // No event to log
      }

      // Get request ID and sensitive paths from store
      const requestId = this.extractRequestId({ event, context: contextObj });
      const sensitivePathsArray = requestId ? (this.sensitivePathsStore.get(requestId) || []) : [];
      
      // Parse the response body if it's a string
      let parsedBody = responseBody;
      if (typeof responseBody === 'string') {
        try {
          parsedBody = JSON.parse(responseBody);
        } catch {
          // If parsing fails, use the string as-is
          parsedBody = responseBody;
        }
      }
      
      // Only mask metadata, not the main data/error fields
      let maskedBody = parsedBody;
      if (parsedBody && typeof parsedBody === 'object' && parsedBody !== null) {
        maskedBody = { ...parsedBody };
        
        // If there's a metadata field, mask only that
        if (maskedBody.metadata) {
          maskedBody.metadata = this.maskSensitiveDataInObject(maskedBody.metadata);
          // Also apply path-based masking if paths are provided
          if (sensitivePathsArray && Array.isArray(sensitivePathsArray) && sensitivePathsArray.length > 0) {
            maskedBody.metadata = this.sensitivePaths(maskedBody.metadata, sensitivePathsArray);
          }
        }
        
        // Apply path-based masking to top-level response body fields if paths are provided
        // This allows masking sensitive fields like email, mnemonic, private_key in the response body
        if (sensitivePathsArray && Array.isArray(sensitivePathsArray) && sensitivePathsArray.length > 0) {
          // Filter paths that start with "responseBody." and remove the prefix for masking the body
          const bodyPaths = sensitivePathsArray
            .filter(path => path.startsWith('responseBody.'))
            .map(path => path.replace(/^responseBody\./, ''));
          
          if (bodyPaths.length > 0) {
            maskedBody = this.sensitivePaths(maskedBody, bodyPaths);
          }
        }
        
        // Keep data and error fields unmasked (they are the main response content)
        // All other fields remain as-is
      } else {
        // For non-object responses, mask the entire thing
        maskedBody = this.maskSensitiveDataInObject(parsedBody);
      }
      
      // Log the response with lifecycle marker
      // The logger will apply sensitive paths to all metadata (request, lambda, etc.)
      this.info('Response sent', {
        lifecycle: 'response',
        statusCode,
        responseBody: maskedBody,
      }, { event, context: contextObj }, sensitivePathsArray);
    } catch (error) {
      // Don't let logging errors break the response
      // Silently fail to avoid disrupting the request flow
      console.error('Failed to log response:', error);
    }
  }

  /**
   * Log an info message
   * @param {string} message - Log message
   * @param {object} logData - Log data to include (optional)
   * @param {object} requestContext - Request context (optional)
   * @param {string[]} pathsToMask - Array of dot-separated paths to mask (optional)
   */
  info(message, logData = null, requestContext = null, pathsToMask = []) {
    const logEntry = this.buildLogEntry('info', message, logData, requestContext, pathsToMask);
    console.log(JSON.stringify(logEntry));
    this.sendToSplunkLambda(logEntry);
  }

  /**
   * Log a warning message
   * @param {string} message - Log message
   * @param {object} logData - Log data to include (optional)
   * @param {object} requestContext - Request context (optional)
   * @param {string[]} pathsToMask - Array of dot-separated paths to mask (optional)
   */
  warn(message, logData = null, requestContext = null, pathsToMask = []) {
    const logEntry = this.buildLogEntry('warn', message, logData, requestContext, pathsToMask);
    console.warn(JSON.stringify(logEntry));
    this.sendToSplunkLambda(logEntry);
  }

  /**
   * Log an error message
   * @param {string} message - Log message
   * @param {Error|object} logData - Error object or log data to include (optional)
   * @param {object} requestContext - Request context (optional)
   * @param {string[]} pathsToMask - Array of dot-separated paths to mask (optional)
   */
  error(message, logData = null, requestContext = null, pathsToMask = []) {
    // Handle Error objects
    const errorData = logData instanceof Error ? {
      errorName: logData.name,
      errorMessage: logData.message,
      errorStack: logData.stack,
    } : logData;
    
    const logEntry = this.buildLogEntry('error', message, errorData, requestContext, pathsToMask);
    console.error(JSON.stringify(logEntry));
    this.sendToSplunkLambda(logEntry);
  }

  /**
   * Log a debug message
   * @param {string} message - Log message
   * @param {object} logData - Log data to include (optional)
   * @param {object} requestContext - Request context (optional)
   * @param {string[]} pathsToMask - Array of dot-separated paths to mask (optional)
   */
  debug(message, logData = null, requestContext = null, pathsToMask = []) {
    const logEntry = this.buildLogEntry('debug', message, logData, requestContext, pathsToMask);
    console.log(JSON.stringify(logEntry));
    this.sendToSplunkLambda(logEntry);
  }

  /**
   * Create a bound logger instance with default request context and sensitive paths
   * This allows for cleaner usage: logger.info('message') instead of logger.info('message', {}, requestContext)
   * @param {object} requestContext - Request context (optional)
   * @param {string[]} defaultSensitivePaths - Array of dot-separated paths to mask by default (optional)
   * @returns {object} Bound logger instance
   */
  createBoundLogger(requestContext = null, defaultSensitivePaths = []) {
    const requestId = this.extractRequestId(requestContext);
    if (requestId && defaultSensitivePaths && Array.isArray(defaultSensitivePaths) && defaultSensitivePaths.length > 0) {
      this.sensitivePathsStore.set(requestId, defaultSensitivePaths);
    }
    
    return {
      info: (message, logData = null, sensitivePathsOverride = null) => {
        const pathsToUse = sensitivePathsOverride !== null && sensitivePathsOverride !== undefined 
          ? sensitivePathsOverride 
          : defaultSensitivePaths;
        let processedLogData = logData;
        if (pathsToUse && Array.isArray(pathsToUse) && pathsToUse.length > 0) {
          processedLogData = this.sensitivePaths(logData, pathsToUse);
        }
        return this.info(message, processedLogData, requestContext, pathsToUse);
      },
      warn: (message, logData = null, sensitivePathsOverride = null) => {
        const pathsToUse = sensitivePathsOverride !== null && sensitivePathsOverride !== undefined 
          ? sensitivePathsOverride 
          : defaultSensitivePaths;
        let processedLogData = logData;
        if (pathsToUse && Array.isArray(pathsToUse) && pathsToUse.length > 0) {
          processedLogData = this.sensitivePaths(logData, pathsToUse);
        }
        return this.warn(message, processedLogData, requestContext, pathsToUse);
      },
      error: (message, logData = null, sensitivePathsOverride = null) => {
        const pathsToUse = sensitivePathsOverride !== null && sensitivePathsOverride !== undefined 
          ? sensitivePathsOverride 
          : defaultSensitivePaths;
        let processedLogData = logData;
        if (pathsToUse && Array.isArray(pathsToUse) && pathsToUse.length > 0) {
          processedLogData = this.sensitivePaths(logData, pathsToUse);
        }
        return this.error(message, processedLogData, requestContext, pathsToUse);
      },
      debug: (message, logData = null, sensitivePathsOverride = null) => {
        const pathsToUse = sensitivePathsOverride !== null && sensitivePathsOverride !== undefined 
          ? sensitivePathsOverride 
          : defaultSensitivePaths;
        let processedLogData = logData;
        if (pathsToUse && Array.isArray(pathsToUse) && pathsToUse.length > 0) {
          processedLogData = this.sensitivePaths(logData, pathsToUse);
        }
        return this.debug(message, processedLogData, requestContext, pathsToUse);
      },
    };
  }
}

module.exports = Logger;

