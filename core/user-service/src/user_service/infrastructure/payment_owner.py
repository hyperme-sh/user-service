"""Read invoice entitlement from payment authority, without foreign SQL."""
import os
import httpx
from pydantic import BaseModel,ConfigDict
import uuid

class InvoiceEntitlement(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    eligible:bool
    user_id:str|None

async def invoice_entitlement(tenant_id:uuid.UUID,billing_id:uuid.UUID):
    url=os.environ.get('PAYMENT_SERVICE_URL','').rstrip('/')
    token=os.environ.get('PAYMENT_USER_EVENT_TOKEN','')
    if not url or not token:raise RuntimeError('Payment owner is not configured')
    async with httpx.AsyncClient(timeout=5,follow_redirects=False) as client:
        response=await client.get(f'{url}/api/v1/payments/internal/invoices/{billing_id}/entitlement',
            headers={'X-Tenant-ID':str(tenant_id),'Authorization':'Bearer '+token})
        response.raise_for_status()
        return InvoiceEntitlement.model_validate(response.json())
