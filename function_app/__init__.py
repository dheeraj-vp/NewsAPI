import azure.functions as func
from supabase import create_client, Client
from dateutil.parser import isoparse
from datetime import datetime, timezone, timedelta
import os
import json
import logging
import hashlib
import time
from typing import Dict, Tuple, Optional

# Redis client for rate limiting
from redis import Redis

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Rate limiting configuration
class RateLimitConfig:
    # Tiered rate limits
    TIERS = {
        "free": {
            "requests_per_minute": 10,
            "requests_per_hour": 100,
            "requests_per_day": 1000,
            "cost_per_1000_requests": 0.00  # Free tier
        },
        "basic": {
            "requests_per_minute": 30,
            "requests_per_hour": 500,
            "requests_per_day": 5000,
            "cost_per_1000_requests": 1.00  # $1.00 per 1000 requests
        },
        "premium": {
            "requests_per_minute": 100,
            "requests_per_hour": 2000,
            "requests_per_day": 20000,
            "cost_per_1000_requests": 0.80  # $0.80 per 1000 requests
        },
        "enterprise": {
            "requests_per_minute": 500,
            "requests_per_hour": 10000,
            "requests_per_day": 100000,
            "cost_per_1000_requests": 0.50  # $0.50 per 1000 requests
        }
    }
    
    # Default rate limits for unauthenticated requests
    DEFAULT_LIMITS = {
        "requests_per_minute": 5,
        "requests_per_hour": 50,
        "requests_per_day": 100,
        "cost_per_1000_requests": 0.00  # Public/anonymous usage
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
            return f"apikey:{api_key}"
        
        # Fallback to IP address
        ip = req.headers.get('X-Forwarded-For') or req.headers.get('X-Real-IP') or '0.0.0.0'
        # Handle comma-separated IP lists (e.g. from proxies)
        if ',' in ip:
            ip = ip.split(',')[0].strip()
            
        return f"ip:{ip}"
    
    def _get_client_tier(self, client_id: str) -> str:
        """
        Determine the client's tier based on their identifier
        In a real implementation, this would lookup the tier in your database
        """
        # For API key clients, lookup their tier from database
        if client_id.startswith("apikey:"):
            api_key = client_id.split(':', 1)[1]
            # This would normally be a database lookup
            # For this example, we're using a simplistic approach
            # API keys starting with specific prefixes map to different tiers
            if api_key.startswith("ent_"):
                return "enterprise"
            elif api_key.startswith("prem_"):
                return "premium"
            elif api_key.startswith("basic_"):
                return "basic"
            else:
                return "free"
        
        # IP-based clients get the default limits
        return "free"
    
    def _get_limits(self, client_id: str) -> Dict:
        """Get the rate limits for the client based on their tier"""
        tier = self._get_client_tier(client_id)
        return self.config.TIERS.get(tier, self.config.DEFAULT_LIMITS)
    
    def check_rate_limit(self, req: func.HttpRequest) -> Tuple[bool, Dict]:
        """
        Check if request is within rate limits and return result with rate limit headers
        Returns a tuple of (is_allowed, headers_dict)
        """
        client_id = self._get_client_identifier(req)
        limits = self._get_limits(client_id)
        tier = self._get_client_tier(client_id)
        
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
        
        # Prepare rate limit headers (following standard practices)
        headers = {
            "X-Rate-Limit-Limit-Minute": str(limits["requests_per_minute"]),
            "X-Rate-Limit-Remaining-Minute": str(max(0, limits["requests_per_minute"] - minute_count)),
            "X-Rate-Limit-Limit-Hour": str(limits["requests_per_hour"]),
            "X-Rate-Limit-Remaining-Hour": str(max(0, limits["requests_per_hour"] - hour_count)),
            "X-Rate-Limit-Limit-Day": str(limits["requests_per_day"]),
            "X-Rate-Limit-Remaining-Day": str(max(0, limits["requests_per_day"] - day_count)),
            "X-Rate-Limit-Reset-Minute": str((now // 60 + 1) * 60),
            "X-Rate-Limit-Reset-Hour": str((now // 3600 + 1) * 3600),
            "X-Rate-Limit-Reset-Day": str((now // 86400 + 1) * 86400),
            "X-Rate-Limit-Tier": tier
        }
        
        is_allowed = minute_allowed and hour_allowed and day_allowed
        return is_allowed, headers
    
    def track_request_cost(self, client_id: str) -> float:
        """
        Calculate the cost of the current request
        In a real implementation, this would be more sophisticated
        """
        tier = self._get_client_tier(client_id)
        limits = self.config.TIERS.get(tier, self.config.DEFAULT_LIMITS)
        
        # Return the cost per request based on tier pricing
        return limits["cost_per_1000_requests"] / 1000


def http_error(message: str, status_code: int, headers: Optional[Dict] = None) -> func.HttpResponse:
    """Return an HTTP error with JSON body and optional headers"""
    response_headers = headers or {}
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        headers=response_headers,
        mimetype="application/json"
    )

# Initialize Redis client
def get_redis_client() -> Redis:
    """Get Redis client from connection string"""
    redis_connection_string = os.environ.get('REDIS_CONNECTION_STRING')
    if not redis_connection_string:
        logging.warning("REDIS_CONNECTION_STRING not configured, using in-memory fallback")
        return DummyRedis()  # Fallback for development/testing
    
    # Parse connection string and create client
    # Format: redis://username:password@host:port
    try:
        return Redis.from_url(redis_connection_string, decode_responses=True)
    except Exception as e:
        logging.error(f"Redis connection error: {str(e)}")
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


@app.route(route="api/articles", methods=["GET"])
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Initialize rate limiter
    redis_client = get_redis_client()
    rate_limiter = RateLimiter(redis_client)
    
    # Check rate limits before processing request
    is_allowed, rate_limit_headers = rate_limiter.check_rate_limit(req)
    
    if not is_allowed:
        retry_after = int(rate_limit_headers["X-Rate-Limit-Reset-Minute"]) - int(time.time())
        rate_limit_headers["Retry-After"] = str(max(1, retry_after))
        return http_error("Rate limit exceeded", 429, rate_limit_headers)

    # Initialize Supabase client
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_KEY')
    if not supabase_url or not supabase_key:
        return http_error("Server configuration error", 500, rate_limit_headers)
    
    try:
        supabase: Client = create_client(supabase_url, supabase_key)
    except Exception as e:
        logging.error(f"Supabase connection error: {str(e)}")
        return http_error("Database connection error", 500, rate_limit_headers)

    # Parse query parameters
    params = {
        'symbol': req.params.get('symbol'),
        'isin': req.params.get('isin'),
        'company': req.params.get('company'),
        'from_date': req.params.get('from'),
        'to_date': req.params.get('to'),
        'article_type': req.params.get('type'),
        'sentiment': req.params.get('sentiment'),
        'limit': req.params.get('limit'),
        'offset': req.params.get('offset')
    }

    # Validate mutually exclusive parameters
    filter_params = [params['symbol'], params['isin'], params['company']]
    if sum(bool(p) for p in filter_params) > 1:
        return http_error("Use only one of: symbol, isin, company", 400, rate_limit_headers)

    # Company lookup logic
    company_name = None
    company_names = []
    if params['symbol']:
        # Lookup company name by symbol
        company = supabase.table('companies').select('name').eq('symbol', params['symbol']).execute()
        if not company.data:
            return http_error(f"Company with symbol '{params['symbol']}' not found", 404, rate_limit_headers)
        company_name = company.data[0]['name']
    elif params['isin']:
        # Lookup company name by ISIN
        company = supabase.table('companies').select('name').eq('ISIN', params['isin']).execute()
        if not company.data:
            return http_error(f"Company with ISIN '{params['isin']}' not found", 404, rate_limit_headers)
        company_name = company.data[0]['name']
    elif params['company']:
        # Find company names matching the input
        companies = supabase.table('companies').select('name').ilike('name', f"%{params['company']}%").execute()
        if not companies.data:
            return http_error(f"No companies found with name containing '{params['company']}'", 404, rate_limit_headers)
        company_names = [c['name'] for c in companies.data]

    # Date parsing and validation
    try:
        from_date = isoparse(params['from_date']) if params['from_date'] else None
        to_date = isoparse(params['to_date']) if params['to_date'] else None
        
        # Convert IST to UTC (Supabase stores timestamps in UTC)
        if from_date:
            from_date = from_date.astimezone(timezone.utc)
        if to_date:
            to_date = to_date.astimezone(timezone.utc)
            
        if from_date and to_date and from_date > to_date:
            return http_error("'from' date must be before 'to' date", 400, rate_limit_headers)
            
    except ValueError as e:
        return http_error(f"Invalid date format: {str(e)}. Use ISO 8601 format (e.g., 2025-01-01T00:00:00+05:30)", 400, rate_limit_headers)

    # Pagination validation
    try:
        limit = int(params['limit']) if params['limit'] else None
        offset = int(params['offset']) if params['offset'] else 0
        if (limit and limit < 0) or offset < 0:
            raise ValueError
    except ValueError:
        return http_error("limit/offset must be non-negative integers", 400, rate_limit_headers)

    # Build query
    try:
        query = supabase.table('articles').select('*')
        
        # Company filtering
        if company_name:
            query = query.eq('company', company_name)
        elif company_names:
            query = query.in_('company', company_names)
        
        # Date filtering
        if from_date:
            query = query.gte('date', from_date.isoformat())
        if to_date:
            query = query.lte('date', to_date.isoformat())
        
        # Additional filters
        if params['article_type']:
            query = query.eq('article_type', params['article_type'])
        if params['sentiment']:
            query = query.eq('sentiment', params['sentiment'])
        
        # Pagination
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)

        # Execute query
        result = query.execute()
        
        # Include rate limit headers in successful response
        response = func.HttpResponse(
            json.dumps(result.data),
            status_code=200,
            headers=rate_limit_headers,
            mimetype="application/json"
        )
        return response
        
    except Exception as e:
        logging.error(f"Database error: {str(e)}")
        return http_error("Internal server error", 500, rate_limit_headers)