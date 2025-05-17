import azure.functions as func
from supabase import create_client, Client
from dateutil.parser import isoparse
from datetime import datetime, timezone, timedelta
import os
import json
import logging
import time
import hashlib
import uuid
import traceback
import re
from typing import Dict, Tuple, Optional, List, Any, Union

# Import API key validation
from api_key_management import validate_api_key

# Redis client for rate limiting
from redis import Redis

# Set up structured logging
logger = logging.getLogger('articles_api')
logger.setLevel(logging.INFO)

# Configuration constants
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
CACHE_TTL = 300  # 5 minutes

# Rate limiting configuration
class RateLimitConfig:
    # Single tier configuration
    STANDARD_TIER = {
        "requests_per_minute": 3,
        "requests_per_hour": 500,
        "requests_per_day": 5000,
        "cost_per_1000_requests": 1.00,  # $1.00 per 1000 requests
        "max_response_size_kb": 1024,    # 1MB response size limit
        "cache_ttl": 300                 # Cache TTL in seconds
    }


class RateLimiter:
    """
    Rate limiter using Redis for tracking request rates
    Implements token bucket algorithm with multiple time windows
    """
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.config = RateLimitConfig()
    
    def _get_client_identifier(self, req: func.HttpRequest) -> str:
        """
        Generate a client identifier from the request
        Uses API key (preferred) or IP address
        """
        # Prefer API key authentication
        api_key = req.headers.get('X-API-Key') or req.params.get('api_key')
        
        if api_key:
            # Validate the API key against database
            is_valid, key_data = validate_api_key(api_key)
            
            if is_valid:
                # Use the database ID as the identifier
                client_id = f"apikey:{key_data['id']}"
                logger.info(f"Request authenticated with valid API key for {key_data['client_name']}")
                return client_id
            else:
                # If key is invalid, fall back to IP tracking
                logger.warning(f"Invalid API key used: {api_key[:8]}...")
        
        # Fallback to IP address
        ip = req.headers.get('X-Forwarded-For') or req.headers.get('X-Real-IP') or '0.0.0.0'
        # Handle comma-separated IP lists (e.g. from proxies)
        if ',' in ip:
            ip = ip.split(',')[0].strip()
            
        return f"ip:{ip}"
    
    def check_rate_limit(self, req: func.HttpRequest) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limits and return result with rate limit headers
        Returns a tuple of (is_allowed, headers_dict)
        """
        client_id = self._get_client_identifier(req)
        limits = self.config.STANDARD_TIER
        
        # Generate a request ID for tracing/debugging
        request_id = str(uuid.uuid4())
        
        # Get current timestamp
        now = int(time.time())
        pipe = self.redis.pipeline()

        # Check and update minute limit
        minute_key = f"{client_id}:minute:{now // 60}"
        pipe.incr(minute_key)
        pipe.expire(minute_key, 90)  # Set TTL to 90 seconds (minute + buffer)
        
        # Check and update hour limit
        hour_key = f"{client_id}:hour:{now // 3600}"
        pipe.incr(hour_key)
        pipe.expire(hour_key, 3700)  # Set TTL to ~1 hour + buffer
        
        # Check and update day limit
        day_key = f"{client_id}:day:{now // 86400}"
        pipe.incr(day_key)
        pipe.expire(day_key, 86500)  # Set TTL to ~1 day + buffer
        
        # Track total requests for billing (persistent counter)
        billing_key = f"{client_id}:billing:{now // 86400}"
        pipe.incr(billing_key)
        pipe.expire(billing_key, 2592000)  # 30 days retention for billing data
        
        # Execute the pipeline
        results = pipe.execute()
        
        minute_count, hour_count, day_count, billing_count = results[0], results[2], results[4], results[6]
        
        # Check if request exceeds any limit
        minute_allowed = minute_count <= limits["requests_per_minute"]
        hour_allowed = hour_count <= limits["requests_per_hour"]
        day_allowed = day_count <= limits["requests_per_day"]
        
        # Calculate reset times
        minute_reset = (now // 60 + 1) * 60
        hour_reset = (now // 3600 + 1) * 3600
        day_reset = (now // 86400 + 1) * 86400
        
        # Prepare rate limit headers (following standard practices)
        headers = {
            "X-Rate-Limit-Limit-Minute": str(limits["requests_per_minute"]),
            "X-Rate-Limit-Remaining-Minute": str(max(0, limits["requests_per_minute"] - minute_count)),
            "X-Rate-Limit-Limit-Hour": str(limits["requests_per_hour"]),
            "X-Rate-Limit-Remaining-Hour": str(max(0, limits["requests_per_hour"] - hour_count)),
            "X-Rate-Limit-Limit-Day": str(limits["requests_per_day"]),
            "X-Rate-Limit-Remaining-Day": str(max(0, limits["requests_per_day"] - day_count)),
            "X-Rate-Limit-Reset-Minute": str(minute_reset),
            "X-Rate-Limit-Reset-Hour": str(hour_reset),
            "X-Rate-Limit-Reset-Day": str(day_reset),
            "X-Rate-Limit-Tier": "standard",
            "X-Request-ID": request_id,
            "Access-Control-Expose-Headers": "X-Rate-Limit-Limit-Minute, X-Rate-Limit-Remaining-Minute, X-Rate-Limit-Reset-Minute, X-Rate-Limit-Tier, X-Request-ID"
        }
        
        # Log rate limit information
        logger.info(f"Rate limit check: client={client_id}, minute={minute_count}/{limits['requests_per_minute']}, hour={hour_count}/{limits['requests_per_hour']}, day={day_count}/{limits['requests_per_day']}, request_id={request_id}")
        
        is_allowed = minute_allowed and hour_allowed and day_allowed
        return is_allowed, headers, request_id
    
    def track_request_cost(self, client_id: str) -> float:
        """
        Calculate the cost of the current request
        """
        limits = self.config.STANDARD_TIER
        
        # Return the cost per request based on tier pricing
        return limits["cost_per_1000_requests"] / 1000


def http_error(message: str, status_code: int, request_id: str = None, headers: Optional[Dict] = None) -> func.HttpResponse:
    """Return an HTTP error with JSON body and optional headers"""
    response_headers = headers or {}
    if request_id:
        response_headers["X-Request-ID"] = request_id
    
    error_response = {
        "error": {
            "message": message,
            "code": status_code,
            "request_id": request_id
        }
    }
    
    return func.HttpResponse(
        json.dumps(error_response),
        status_code=status_code,
        headers=response_headers,
        mimetype="application/json"
    )


def http_success(data: Any, headers: Dict, status_code: int = 200) -> func.HttpResponse:
    """Return a successful HTTP response with JSON body and headers"""
    return func.HttpResponse(
        json.dumps(data),
        status_code=status_code,
        headers=headers,
        mimetype="application/json"
    )


# Initialize Redis client
def get_redis_client() -> Redis:
    """Get Redis client from connection string"""
    redis_connection_string = os.environ.get('REDIS_CONNECTION_STRING')
    if not redis_connection_string:
        logger.warning("REDIS_CONNECTION_STRING not configured, using in-memory fallback")
        return DummyRedis()  # Fallback for development/testing
    
    # Parse connection string and create client
    # Format: redis://username:password@host:port
    try:
        return Redis.from_url(redis_connection_string, decode_responses=True)
    except Exception as e:
        logger.error(f"Redis connection error: {str(e)}")
        return DummyRedis()  # Fallback on connection error


class DummyRedis:
    """In-memory fallback when Redis is unavailable"""
    def __init__(self):
        self.data = {}
        self.ttl = {}
    
    def incr(self, key):
        if key not in self.data:
            self.data[key] = 0
        self.data[key] += 1
        return self.data[key]
    
    def expire(self, key, seconds):
        self.ttl[key] = time.time() + seconds
        return True
    
    def pipeline(self):
        return DummyRedisPipeline(self)
    
    def get(self, key):
        # Check if key exists and TTL hasn't expired
        if key in self.data and key in self.ttl and time.time() < self.ttl[key]:
            return self.data[key]
        return None
    
    def set(self, key, value, ex=None):
        self.data[key] = value
        if ex is not None:
            self.ttl[key] = time.time() + ex
        return True


class DummyRedisPipeline:
    """In-memory Redis Pipeline implementation"""
    def __init__(self, dummy_redis):
        self.dummy_redis = dummy_redis
        self.commands = []
    
    def incr(self, key):
        self.commands.append(("incr", key))
        return self
    
    def expire(self, key, seconds):
        self.commands.append(("expire", key, seconds))
        return self
    
    def execute(self):
        results = []
        for cmd in self.commands:
            if cmd[0] == "incr":
                results.append(self.dummy_redis.incr(cmd[1]))
            elif cmd[0] == "expire":
                results.append(self.dummy_redis.expire(cmd[1], cmd[2]))
        return results


class Cache:
    """Simple caching layer using Redis"""
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.ttl = RateLimitConfig.STANDARD_TIER["cache_ttl"]
    
    def get(self, key: str) -> Optional[str]:
        """Get a value from cache"""
        return self.redis.get(key)
    
    def set(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Store a value in cache with TTL"""
        return self.redis.set(key, value, ex=ttl or self.ttl)
    
    def generate_cache_key(self, req: func.HttpRequest) -> str:
        """Generate a cache key from the request"""
        # Sort params to ensure consistent ordering
        params = {k: v for k, v in req.params.items()}
        sorted_params = json.dumps(params, sort_keys=True)
        
        # Hash the params to create a short but unique key
        hashed_params = hashlib.md5(sorted_params.encode()).hexdigest()
        
        # Include HTTP method and path in the key
        method = req.method or "GET"
        path = req.url.split("?")[0] if req.url else "/"
        
        return f"cache:{method}:{path}:{hashed_params}"


class QueryValidator:
    """Validate and sanitize query parameters"""
    
    @staticmethod
    def validate_string(value: Optional[str], pattern: str = None, max_length: int = 50) -> Optional[str]:
        """Validate and sanitize a string parameter"""
        if not value:
            return None
        
        # Truncate if too long
        value = value[:max_length] if len(value) > max_length else value
        
        # Validate pattern if provided
        if pattern and not re.match(pattern, value):
            return None
            
        return value
    
    @staticmethod
    def validate_date(value: Optional[str]) -> Optional[datetime]:
        """Validate and parse a date parameter"""
        if not value:
            return None
            
        try:
            # Parse ISO date string
            dt = isoparse(value)
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return None
    
    @staticmethod
    def validate_int(value: Optional[str], min_val: int = 0, max_val: int = 1000) -> Optional[int]:
        """Validate and parse an integer parameter"""
        if not value:
            return None
            
        try:
            int_val = int(value)
            if min_val <= int_val <= max_val:
                return int_val
        except (ValueError, TypeError):
            pass
            
        return None


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main entry point for the articles API endpoint
    """
    # Start time for performance tracking
    start_time = time.time()

    # Get request details for logging
    req_method = req.method
    req_url = req.url
    req_client_ip = req.headers.get('X-Forwarded-For') or req.headers.get('X-Real-IP') or '0.0.0.0'
    if ',' in req_client_ip:
        req_client_ip = req_client_ip.split(',')[0].strip()

    logger.info(f"Request received: {req_method} {req_url} from {req_client_ip}")

    # Initialize rate limiter
    redis_client = get_redis_client()
    rate_limiter = RateLimiter(redis_client)
    
    # Initialize cache
    cache = Cache(redis_client)
    
    # Check if request is cached
    cache_key = None
    if req.method == "GET":
        cache_key = cache.generate_cache_key(req)
        cached_response = cache.get(cache_key)
        if cached_response:
            # Process rate limits even for cached responses
            is_allowed, rate_limit_headers, request_id = rate_limiter.check_rate_limit(req)
            if not is_allowed:
                retry_after = int(rate_limit_headers["X-Rate-Limit-Reset-Minute"]) - int(time.time())
                rate_limit_headers["Retry-After"] = str(max(1, retry_after))
                return http_error("Rate limit exceeded", 429, request_id, rate_limit_headers)
                
            # Add cache hit headers
            rate_limit_headers["X-Cache"] = "HIT"
            rate_limit_headers["X-Request-ID"] = request_id
            logger.info(f"Cache hit: {cache_key}, request_id={request_id}")
            
            # Create HTTP response from cached data
            cached_data = json.loads(cached_response)
            return http_success(cached_data, rate_limit_headers)
    
    # Check rate limits before processing request
    is_allowed, rate_limit_headers, request_id = rate_limiter.check_rate_limit(req)
    
    if not is_allowed:
        retry_after = int(rate_limit_headers["X-Rate-Limit-Reset-Minute"]) - int(time.time())
        rate_limit_headers["Retry-After"] = str(max(1, retry_after))
        logger.warning(f"Rate limit exceeded: request_id={request_id}")
        return http_error("Rate limit exceeded", 429, request_id, rate_limit_headers)

    # Add cache miss header
    if cache_key:
        rate_limit_headers["X-Cache"] = "MISS"

    # Initialize Supabase client
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_KEY')
    if not supabase_url or not supabase_key:
        logger.error(f"Missing Supabase configuration, request_id={request_id}")
        return http_error("Server configuration error", 500, request_id, rate_limit_headers)
    
    try:
        supabase: Client = create_client(supabase_url, supabase_key)
    except Exception as e:
        logger.error(f"Supabase connection error: {str(e)}, request_id={request_id}")
        return http_error("Database connection error", 500, request_id, rate_limit_headers)

    # Parse and validate query parameters
    validator = QueryValidator()
    params = {
        'symbol': validator.validate_string(req.params.get('symbol'), pattern=r'^[A-Z0-9.]{1,10}$'),
        'isin': validator.validate_string(req.params.get('isin'), pattern=r'^[A-Z0-9]{12}$'),
        'company': validator.validate_string(req.params.get('company'), max_length=100),
        'from_date': validator.validate_date(req.params.get('from')),
        'to_date': validator.validate_date(req.params.get('to')),
        'article_type': validator.validate_string(req.params.get('type'), pattern=r'^[a-zA-Z0-9_-]{1,20}$'),
        'sentiment': validator.validate_string(req.params.get('sentiment'), pattern=r'^(positive|negative|neutral)$'),
        'limit': validator.validate_int(req.params.get('limit'), max_val=MAX_LIMIT) or DEFAULT_LIMIT,
        'offset': validator.validate_int(req.params.get('offset')) or 0,
        'sort': validator.validate_string(req.params.get('sort'), pattern=r'^(date|company|title)$') or 'date',
        'order': validator.validate_string(req.params.get('order'), pattern=r'^(asc|desc)$') or 'desc'
    }

    # Log request parameters
    logger.info(f"Request parameters: {json.dumps({k: str(v) for k, v in params.items()})}, request_id={request_id}")

    # Validate mutually exclusive parameters
    filter_params = [params['symbol'], params['isin'], params['company']]
    if sum(bool(p) for p in filter_params) > 1:
        logger.warning(f"Mutually exclusive parameters provided, request_id={request_id}")
        return http_error("Use only one of: symbol, isin, company", 400, request_id, rate_limit_headers)

    # Company lookup logic
    company_name = None
    company_names = []
    try:
        if params['symbol']:
            # Lookup company name by symbol
            company = supabase.table('companies').select('name').eq('symbol', params['symbol']).execute()
            if not company.data:
                return http_error(f"Company with symbol '{params['symbol']}' not found", 404, request_id, rate_limit_headers)
            company_name = company.data[0]['name']
        elif params['isin']:
            # Lookup company name by ISIN
            company = supabase.table('companies').select('name').eq('ISIN', params['isin']).execute()
            if not company.data:
                return http_error(f"Company with ISIN '{params['isin']}' not found", 404, request_id, rate_limit_headers)
            company_name = company.data[0]['name']
        elif params['company']:
            # Find company names matching the input
            companies = supabase.table('companies').select('name').ilike('name', f"%{params['company']}%").execute()
            if not companies.data:
                return http_error(f"No companies found with name containing '{params['company']}'", 404, request_id, rate_limit_headers)
            company_names = [c['name'] for c in companies.data]
    except Exception as e:
        logger.error(f"Company lookup error: {str(e)}, request_id={request_id}")
        return http_error("Error looking up company information", 500, request_id, rate_limit_headers)

    # Date validation
    if params['from_date'] and params['to_date'] and params['from_date'] > params['to_date']:
        logger.warning(f"Invalid date range: from_date > to_date, request_id={request_id}")
        return http_error("'from' date must be before 'to' date", 400, request_id, rate_limit_headers)

    # Build query
    try:
        # First query to get total count for pagination
        count_query = supabase.table('articles').select('*', count='exact')
        
        # Apply filters to count query
        if company_name:
            count_query = count_query.eq('company', company_name)
        elif company_names:
            count_query = count_query.in_('company', company_names)
        
        # Date filtering
        if params['from_date']:
            count_query = count_query.gte('date', params['from_date'].isoformat())
        if params['to_date']:
            count_query = count_query.lte('date', params['to_date'].isoformat())
        
        # Additional filters
        if params['article_type']:
            count_query = count_query.eq('article_type', params['article_type'])
        if params['sentiment']:
            count_query = count_query.eq('sentiment', params['sentiment'])
            
        # Execute count query to get total results
        count_result = count_query.execute()
        total_count = count_result.count
        
        # Now build the main query with pagination
        query = supabase.table('articles').select('*')
        
        # Company filtering
        if company_name:
            query = query.eq('company', company_name)
        elif company_names:
            query = query.in_('company', company_names)
        
        # Date filtering
        if params['from_date']:
            query = query.gte('date', params['from_date'].isoformat())
        if params['to_date']:
            query = query.lte('date', params['to_date'].isoformat())
        
        # Additional filters
        if params['article_type']:
            query = query.eq('article_type', params['article_type'])
        if params['sentiment']:
            query = query.eq('sentiment', params['sentiment'])
        
        # Sorting
        sort_order = params['order']
        query = query.order(params['sort'], desc=(sort_order == 'desc'))
        
        # Pagination
        query = query.limit(params['limit']).offset(params['offset'])

        # Execute query
        result = query.execute()
        
        # Calculate pagination metadata
        page_size = params['limit']
        current_page = params['offset'] // page_size + 1 if page_size > 0 else 1
        total_pages = (total_count + page_size - 1) // page_size if page_size > 0 else 1
        
        # Prepare response with pagination metadata
        response_data = {
            "data": result.data,
            "pagination": {
                "total": total_count,
                "per_page": page_size,
                "current_page": current_page,
                "total_pages": total_pages,
                "has_next_page": current_page < total_pages,
                "has_prev_page": current_page > 1
            },
            "meta": {
                "request_id": request_id,
                "elapsed_ms": int((time.time() - start_time) * 1000)
            }
        }
        
        # Cache the response if it's a GET request
        if cache_key:
            cache.set(cache_key, json.dumps(response_data))
            logger.info(f"Cached response: {cache_key}, request_id={request_id}")
        
        # Include rate limit headers in successful response
        rate_limit_headers["X-Response-Time-Ms"] = str(int((time.time() - start_time) * 1000))
        
        logger.info(f"Request completed successfully: found {len(result.data)} results, total {total_count}, request_id={request_id}, elapsed_ms={(time.time() - start_time) * 1000:.2f}")
        return http_success(response_data, rate_limit_headers)
        
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Database error: {str(e)}, request_id={request_id}\n{error_details}")
        return http_error("Internal server error", 500, request_id, rate_limit_headers)