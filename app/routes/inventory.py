"""
Inventory API - Track software, certificates, and hardware
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from app.security import get_current_user
from app.models import User

router = APIRouter(prefix="/inventory", tags=["inventory"])


class InventoryItem(BaseModel):
    id: int
    name: str
    type: str
    category: str
    status: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    license_key: Optional[str] = None
    expiration_date: Optional[str] = None
    assigned_to: Optional[str] = None
    location: Optional[str] = None
    serial_number: Optional[str] = None
    notes: Optional[str] = None
    metadata: dict = {}
    created_at: str
    updated_at: str


class InventoryItemCreate(BaseModel):
    name: str
    type: str
    category: str
    status: str = "active"
    vendor: Optional[str] = None
    version: Optional[str] = None
    license_key: Optional[str] = None
    expiration_date: Optional[str] = None
    assigned_to: Optional[str] = None
    location: Optional[str] = None
    serial_number: Optional[str] = None
    notes: Optional[str] = None


inventory_db = [
    {
        "id": 1,
        "name": "Microsoft 365 E5",
        "type": "software",
        "category": "Productivity Suite",
        "status": "active",
        "vendor": "Microsoft",
        "version": "2024.01",
        "license_key": "XXXXX-XXXXX-XXXXX",
        "expiration_date": "2025-12-31",
        "assigned_to": "Acme Corp",
        "location": "Cloud",
        "serial_number": None,
        "notes": "Enterprise license with security features",
        "metadata": {"seats": 500, "used": 487},
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-03-01T14:30:00Z",
    },
    {
        "id": 2,
        "name": "AWS Root CA",
        "type": "certificate",
        "category": "SSL/TLS Certificate",
        "status": "active",
        "vendor": "Amazon",
        "version": None,
        "license_key": "arn:aws:acm:us-east-1:123456789:certificate/abc123",
        "expiration_date": "2026-06-15",
        "assigned_to": "api.guardrail.ai",
        "location": "us-east-1",
        "serial_number": "04:FB:9A:CD:...",
        "notes": "Wildcard certificate for *.guardrail.ai",
        "metadata": {"domain": "*.guardrail.ai", "issuer": "Amazon"},
        "created_at": "2024-02-01T08:00:00Z",
        "updated_at": "2024-02-15T11:00:00Z",
    },
    {
        "id": 3,
        "name": "Dell PowerEdge R740",
        "type": "hardware",
        "category": "Server",
        "status": "active",
        "vendor": "Dell",
        "version": "2U",
        "license_key": None,
        "expiration_date": None,
        "assigned_to": "Production",
        "location": "DC-1 Rack A-12",
        "serial_number": "SN-2024-001234",
        "notes": "Primary application server",
        "metadata": {
            "cpu": "Intel Xeon Gold 6248",
            "ram": "256GB",
            "storage": "8TB SSD",
        },
        "created_at": "2024-01-10T09:00:00Z",
        "updated_at": "2024-03-15T16:00:00Z",
    },
    {
        "id": 4,
        "name": "Slack Enterprise",
        "type": "software",
        "category": "Communication",
        "status": "active",
        "vendor": "Salesforce",
        "version": "Q1 2024",
        "license_key": "WORKSPACE-XXXXX",
        "expiration_date": "2025-03-01",
        "assigned_to": "Acme Corp",
        "location": "Cloud",
        "serial_number": None,
        "notes": "Team communication platform",
        "metadata": {"seats": 300, "active_users": 245},
        "created_at": "2024-02-20T10:00:00Z",
        "updated_at": "2024-03-01T10:00:00Z",
    },
    {
        "id": 5,
        "name": "Fortinet FortiGate 600E",
        "type": "hardware",
        "category": "Network Security",
        "status": "active",
        "vendor": "Fortinet",
        "version": "7.4.2",
        "license_key": None,
        "expiration_date": None,
        "assigned_to": "Network",
        "location": "DC-1 Rack B-01",
        "serial_number": "FG6E-2024-5678",
        "notes": "Edge firewall appliance",
        "metadata": {"throughput": "20Gbps", "interfaces": "18 ports"},
        "created_at": "2024-01-05T08:00:00Z",
        "updated_at": "2024-02-28T09:00:00Z",
    },
    {
        "id": 6,
        "name": "DigiCert EV SSL",
        "type": "certificate",
        "category": "SSL/TLS Certificate",
        "status": "active",
        "vendor": "DigiCert",
        "version": None,
        "license_key": "cert-2024-ev-12345",
        "expiration_date": "2025-08-20",
        "assigned_to": "www.guardrail.ai",
        "location": "Cloudflare",
        "serial_number": "0A:1B:2C:3D:...",
        "notes": "Extended Validation certificate",
        "metadata": {
            "domain": "www.guardrail.ai",
            "issuer": "DigiCert SHA2 Extended Validation",
        },
        "created_at": "2024-02-15T12:00:00Z",
        "updated_at": "2024-02-15T12:00:00Z",
    },
    {
        "id": 7,
        "name": 'MacBook Pro 16" M3',
        "type": "hardware",
        "category": "Laptop",
        "status": "active",
        "vendor": "Apple",
        "version": "M3 Pro",
        "license_key": None,
        "expiration_date": None,
        "assigned_to": "John Smith",
        "location": "Office",
        "serial_number": "C02X1234ABCD",
        "notes": "Developer workstation",
        "metadata": {"ram": "36GB", "storage": "512GB"},
        "created_at": "2024-03-01T14:00:00Z",
        "updated_at": "2024-03-01T14:00:00Z",
    },
    {
        "id": 8,
        "name": "Jira Software Cloud",
        "type": "software",
        "category": "Project Management",
        "status": "active",
        "vendor": "Atlassian",
        "version": "Cloud",
        "license_key": "atlassian-xxxxx",
        "expiration_date": "2025-01-15",
        "assigned_to": "Acme Corp",
        "location": "Cloud",
        "serial_number": None,
        "notes": "Project tracking and agile management",
        "metadata": {"seats": 100, "active_users": 87},
        "created_at": "2024-02-01T09:00:00Z",
        "updated_at": "2024-03-10T11:00:00Z",
    },
]


@router.get("/", response_model=List[dict])
def list_inventory(
    type: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """List inventory items with optional filtering."""
    results = inventory_db

    if type:
        results = [i for i in results if i["type"] == type]
    if category:
        results = [i for i in results if i["category"] == category]
    if status:
        results = [i for i in results if i["status"] == status]
    if search:
        search_lower = search.lower()
        results = [
            i
            for i in results
            if search_lower in i["name"].lower()
            or search_lower in (i.get("vendor") or "").lower()
        ]

    return results


@router.get("/{item_id}", response_model=dict)
def get_inventory_item(
    item_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get detailed inventory item."""
    for item in inventory_db:
        if item["id"] == item_id:
            return item
    raise HTTPException(status_code=404, detail="Item not found")


@router.post("/", response_model=dict)
def create_inventory_item(
    item: InventoryItemCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new inventory item."""
    new_id = max(i["id"] for i in inventory_db) + 1
    new_item = {
        "id": new_id,
        **item.model_dump(),
        "metadata": {},
        "created_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "updated_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
    }
    inventory_db.append(new_item)
    return new_item


@router.put("/{item_id}", response_model=dict)
def update_inventory_item(
    item_id: int,
    item: InventoryItemCreate,
    current_user: User = Depends(get_current_user),
):
    """Update an inventory item."""
    for i, existing in enumerate(inventory_db):
        if existing["id"] == item_id:
            inventory_db[i] = {
                **existing,
                **item.model_dump(),
                "updated_at": datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            }
            return inventory_db[i]
    raise HTTPException(status_code=404, detail="Item not found")


@router.delete("/{item_id}")
def delete_inventory_item(
    item_id: int,
    current_user: User = Depends(get_current_user),
):
    """Delete an inventory item."""
    for i, item in enumerate(inventory_db):
        if item["id"] == item_id:
            inventory_db.pop(i)
            return {"message": "Item deleted"}
    raise HTTPException(status_code=404, detail="Item not found")


@router.get("/summary/types")
def get_type_summary(current_user: User = Depends(get_current_user)):
    """Get summary of items by type."""
    types = {}
    for item in inventory_db:
        t = item["type"]
        if t not in types:
            types[t] = {"count": 0, "active": 0, "expired": 0}
        types[t]["count"] += 1
        if item["status"] == "active":
            types[t]["active"] += 1
    return types


@router.get("/summary/expiring")
def get_expiring_items(
    days: int = 30,
    current_user: User = Depends(get_current_user),
):
    """Get items expiring within specified days."""
    from datetime import timedelta

    cutoff = (datetime.now(tz=timezone.utc).replace(tzinfo=None) + timedelta(days=days)).isoformat()[:10]

    expiring = [
        item
        for item in inventory_db
        if item.get("expiration_date") and item["expiration_date"] <= cutoff
    ]
    return expiring
