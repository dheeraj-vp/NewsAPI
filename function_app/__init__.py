import azure.functions as func
from supabase import create_client, Client
from dateutil.parser import isoparse
from datetime import datetime, timezone
import os
import json
import logging

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def http_error(message: str, status_code: int) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        mimetype="application/json"
    )

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Initialize Supabase client
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_KEY')
    if not supabase_url or not supabase_key:
        return http_error("Server configuration error", 500)
    
    try:
        supabase: Client = create_client(supabase_url, supabase_key)
    except Exception as e:
        logging.error(f"Supabase connection error: {str(e)}")
        return http_error("Database connection error", 500)

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
        return http_error("Use only one of: symbol, isin, company", 400)

    # Company lookup logic
    company_name = None
    company_names = []
    if params['symbol']:
        # Lookup company name by symbol
        company = supabase.table('companies').select('name').eq('symbol', params['symbol']).execute()
        if not company.data:
            return http_error(f"Company with symbol '{params['symbol']}' not found", 404)
        company_name = company.data[0]['name']
    elif params['isin']:
        # Lookup company name by ISIN
        company = supabase.table('companies').select('name').eq('ISIN', params['isin']).execute()
        if not company.data:
            return http_error(f"Company with ISIN '{params['isin']}' not found", 404)
        company_name = company.data[0]['name']
    elif params['company']:
        # Find company names matching the input
        companies = supabase.table('companies').select('name').ilike('name', f"%{params['company']}%").execute()
        if not companies.data:
            return http_error(f"No companies found with name containing '{params['company']}'", 404)
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
            return http_error("'from' date must be before 'to' date", 400)
            
    except ValueError as e:
        return http_error(f"Invalid date format: {str(e)}. Use ISO 8601 format (e.g., 2023-01-01T00:00:00+05:30)", 400)

    # Pagination validation
    try:
        limit = int(params['limit']) if params['limit'] else None
        offset = int(params['offset']) if params['offset'] else 0
        if (limit and limit < 0) or offset < 0:
            raise ValueError
    except ValueError:
        return http_error("limit/offset must be non-negative integers", 400)

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

        result = query.execute()
        return func.HttpResponse(
            json.dumps(result.data),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Database error: {str(e)}")
        return http_error("Internal server error", 500)