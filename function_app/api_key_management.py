import azure.functions as func
from supabase import create_client, Client
import os
import json
import logging
import uuid
import hashlib
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Tuple, Any

# Set up structured logging
logger = logging.getLogger('api_key_management')
logger.setLevel(logging.INFO)

def initialize_supabase() -> Optional[Client]:
    """Initialize and return a Supabase client"""
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_KEY')
    
    if not supabase_url or not supabase_key:
        logger.error("Missing Supabase configuration")
        return None
    
    try:
        return create_client(supabase_url, supabase_key)
    except Exception as e:
        logger.error(f"Supabase connection error: {str(e)}")
        return None

def generate_api_key() -> str:
    """Generate a new API key with format 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"""
    random_part = uuid.uuid4().hex + uuid.uuid4().hex
    return f"sk_live_{random_part[:32]}"

def hash_api_key(api_key: str) -> str:
    """Create a secure hash of the API key for storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()

def create_client_api_key(client_name: str, client_email: str, description: str = None) -> Dict:
    """
    Create a new API key for a client
    
    Args:
        client_name: Name of the client/company
        client_email: Email address for contact
        description: Optional description of the API key usage
        
    Returns:
        Dictionary with the API key information and status
    """
    supabase = initialize_supabase()
    if not supabase:
        return {"success": False, "error": "Database connection error"}
    
    try:
        # Generate a new API key
        api_key = generate_api_key()
        api_key_hash = hash_api_key(api_key)
        
        # Create API key record
        now = datetime.now(timezone.utc).isoformat()
        key_data = {
            "client_name": client_name,
            "client_email": client_email,
            "description": description or f"API key for {client_name}",
            "key_hash": api_key_hash,
            "tier": "standard",  # Only using the standard tier
            "created_at": now,
            "last_used": None,
            "is_active": True
        }
        
        # Insert into database
        result = supabase.table('api_keys').insert(key_data).execute()
        
        if not result.data:
            return {"success": False, "error": "Failed to create API key"}
        
        # Return information about the new API key
        # Important: This is the only time the full API key will be available
        return {
            "success": True,
            "api_key": api_key,
            "client_name": client_name,
            "tier": "standard",
            "created_at": now,
            "message": "Store this API key securely. It won't be displayed again."
        }
        
    except Exception as e:
        logger.error(f"Error creating API key: {str(e)}")
        return {"success": False, "error": f"Error creating API key: {str(e)}"}

def list_client_api_keys(client_email: Optional[str] = None) -> Dict:
    """
    List all API keys or filter by client email
    
    Args:
        client_email: Optional email to filter results
        
    Returns:
        Dictionary with list of API keys (not including the actual keys)
    """
    supabase = initialize_supabase()
    if not supabase:
        return {"success": False, "error": "Database connection error"}
    
    try:
        # Build query
        query = supabase.table('api_keys').select(
            'id,client_name,client_email,description,tier,created_at,last_used,is_active'
        )
        
        # Filter by client email if provided
        if client_email:
            query = query.eq('client_email', client_email)
        
        # Execute query
        result = query.execute()
        
        return {
            "success": True,
            "keys": result.data
        }
        
    except Exception as e:
        logger.error(f"Error listing API keys: {str(e)}")
        return {"success": False, "error": f"Error listing API keys: {str(e)}"}

def revoke_api_key(key_id: str) -> Dict:
    """
    Revoke (deactivate) an API key
    
    Args:
        key_id: Database ID of the key to revoke
        
    Returns:
        Dictionary with operation status
    """
    supabase = initialize_supabase()
    if not supabase:
        return {"success": False, "error": "Database connection error"}
    
    try:
        # Update the key status
        result = supabase.table('api_keys').update(
            {"is_active": False}
        ).eq('id', key_id).execute()
        
        if not result.data:
            return {"success": False, "error": "API key not found"}
        
        return {
            "success": True,
            "message": "API key revoked successfully"
        }
        
    except Exception as e:
        logger.error(f"Error revoking API key: {str(e)}")
        return {"success": False, "error": f"Error revoking API key: {str(e)}"}

def validate_api_key(api_key: str) -> Tuple[bool, Optional[Dict]]:
    """
    Validate an API key and return its associated data
    
    Args:
        api_key: The API key to validate
        
    Returns:
        Tuple of (is_valid, key_data)
    """
    if not api_key or not api_key.startswith("sk_live_"):
        return False, None
    
    supabase = initialize_supabase()
    if not supabase:
        return False, None
    
    try:
        # Hash the key for lookup
        key_hash = hash_api_key(api_key)
        
        # Look up the key
        result = supabase.table('api_keys').select('*').eq('key_hash', key_hash).eq('is_active', True).execute()
        
        if not result.data:
            return False, None
        
        key_data = result.data[0]
        
        # Update last_used timestamp
        supabase.table('api_keys').update(
            {"last_used": datetime.now(timezone.utc).isoformat()}
        ).eq('id', key_data['id']).execute()
        
        return True, key_data
        
    except Exception as e:
        logger.error(f"Error validating API key: {str(e)}")
        return False, None

# HTTP handlers for API key management
def handle_api_key_creation(req: func.HttpRequest) -> func.HttpResponse:
    """Handle API key creation requests"""
    try:
        # Parse request body
        req_body = req.get_json()
        
        # Validate input
        client_name = req_body.get('client_name')
        client_email = req_body.get('client_email')
        description = req_body.get('description')
        
        if not client_name or not client_email:
            return func.HttpResponse(
                json.dumps({"error": "client_name and client_email are required"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Admin authorization check (implement as needed)
        admin_key = req.headers.get('X-Admin-Key')
        if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY'):
            return func.HttpResponse(
                json.dumps({"error": "Unauthorized. Admin access required"}),
                status_code=401,
                mimetype="application/json"
            )
        
        # Create the API key
        result = create_client_api_key(client_name, client_email, description)
        
        if not result["success"]:
            return func.HttpResponse(
                json.dumps(result),
                status_code=500,
                mimetype="application/json"
            )
        
        return func.HttpResponse(
            json.dumps(result),
            status_code=201,
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"Error handling API key creation: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Error creating API key: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def handle_api_key_listing(req: func.HttpRequest) -> func.HttpResponse:
    """Handle API key listing requests"""
    try:
        # Admin authorization check
        admin_key = req.headers.get('X-Admin-Key')
        if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY'):
            return func.HttpResponse(
                json.dumps({"error": "Unauthorized. Admin access required"}),
                status_code=401,
                mimetype="application/json"
            )
        
        # Get optional client email filter
        client_email = req.params.get('client_email')
        
        # Get the list of keys
        result = list_client_api_keys(client_email)
        
        if not result["success"]:
            return func.HttpResponse(
                json.dumps(result),
                status_code=500,
                mimetype="application/json"
            )
        
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"Error handling API key listing: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Error listing API keys: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

def handle_api_key_revocation(req: func.HttpRequest) -> func.HttpResponse:
    """Handle API key revocation requests"""
    try:
        # Parse request body
        req_body = req.get_json()
        
        # Validate input
        key_id = req_body.get('key_id')
        
        if not key_id:
            return func.HttpResponse(
                json.dumps({"error": "key_id is required"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Admin authorization check
        admin_key = req.headers.get('X-Admin-Key')
        if not admin_key or admin_key != os.environ.get('ADMIN_API_KEY'):
            return func.HttpResponse(
                json.dumps({"error": "Unauthorized. Admin access required"}),
                status_code=401,
                mimetype="application/json"
            )
        
        # Revoke the key
        result = revoke_api_key(key_id)
        
        if not result["success"]:
            return func.HttpResponse(
                json.dumps(result),
                status_code=500,
                mimetype="application/json"
            )
        
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"Error handling API key revocation: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Error revoking API key: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )