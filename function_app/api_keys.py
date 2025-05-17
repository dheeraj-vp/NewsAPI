import azure.functions as func
import json
import logging
import os

from api_key_management import (
    handle_api_key_creation,
    handle_api_key_listing,
    handle_api_key_revocation
)

# Set up logging
logger = logging.getLogger('api_key_function')
logger.setLevel(logging.INFO)

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint for API key management
    
    Routes:
    - POST /api/keys : Create a new API key
    - GET /api/keys : List API keys
    - DELETE /api/keys : Revoke an API key
    """
    logger.info(f"API key management request: {req.method} {req.url}")
    
    try:
        # Route based on HTTP method
        if req.method == "POST":
            return handle_api_key_creation(req)
        elif req.method == "GET":
            return handle_api_key_listing(req)
        elif req.method == "DELETE":
            return handle_api_key_revocation(req)
        else:
            return func.HttpResponse(
                json.dumps({"error": "Method not allowed"}),
                status_code=405,
                mimetype="application/json"
            )
    except Exception as e:
        logger.error(f"Error in API key management: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Internal server error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )