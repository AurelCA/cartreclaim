from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import httpx
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).parent

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"

# Create the main app
app = FastAPI(title="CartReclaim - Abandoned Cart Recovery SaaS")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ======================= MODELS =======================

class UserBase(BaseModel):
    email: EmailStr
    name: str = ""

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str = ""

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    user_id: str
    email: str
    name: str
    role: str = "user"
    store_name: Optional[str] = None
    store_url: Optional[str] = None
    shopify_connected: bool = False
    created_at: datetime

class StoreSettings(BaseModel):
    store_name: str
    store_url: str
    currency: str = "USD"
    timezone: str = "UTC"

class AbandonedCart(BaseModel):
    cart_id: str
    user_id: str
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    items: List[dict]
    total_value: float
    status: str = "pending"  # pending, recovered, lost
    created_at: datetime
    updated_at: datetime
    recovery_attempts: int = 0
    recovered_at: Optional[datetime] = None

class AbandonedCartCreate(BaseModel):
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    items: List[dict]
    total_value: float

class EmailCampaign(BaseModel):
    campaign_id: str
    user_id: str
    name: str
    subject: str
    template: str
    delay_hours: int = 1
    discount_code: Optional[str] = None
    discount_percent: Optional[int] = None
    is_active: bool = True
    created_at: datetime
    emails_sent: int = 0
    emails_opened: int = 0
    conversions: int = 0

class EmailCampaignCreate(BaseModel):
    name: str
    subject: str
    template: str
    delay_hours: int = 1
    discount_code: Optional[str] = None
    discount_percent: Optional[int] = None
    is_active: bool = True

class PopupConfig(BaseModel):
    popup_id: str
    user_id: str
    title: str
    message: str
    discount_code: Optional[str] = None
    discount_percent: Optional[int] = None
    background_color: str = "#4F46E5"
    text_color: str = "#FFFFFF"
    button_text: str = "Claim Offer"
    is_active: bool = True
    trigger_type: str = "exit_intent"  # exit_intent, time_delay, scroll
    trigger_value: int = 0  # seconds for time_delay, percentage for scroll
    created_at: datetime
    impressions: int = 0
    conversions: int = 0

class PopupConfigCreate(BaseModel):
    title: str
    message: str
    discount_code: Optional[str] = None
    discount_percent: Optional[int] = None
    background_color: str = "#4F46E5"
    text_color: str = "#FFFFFF"
    button_text: str = "Claim Offer"
    is_active: bool = True
    trigger_type: str = "exit_intent"
    trigger_value: int = 0

class AIInsightRequest(BaseModel):
    question: Optional[str] = None

class RecoveryEmail(BaseModel):
    cart_id: str
    recipient_email: EmailStr

# ======================= AUTH HELPERS =======================

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=60),
        "type": "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "refresh"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"user_id": payload["sub"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ======================= AUTH ENDPOINTS =======================

@api_router.post("/auth/register")
async def register(response: Response, input: UserCreate):
    email = input.email.lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = f"user_{uuid.uuid4().hex[:12]}"
    user_doc = {
        "user_id": user_id,
        "email": email,
        "name": input.name or email.split("@")[0],
        "password_hash": hash_password(input.password),
        "role": "user",
        "store_name": None,
        "store_url": None,
        "shopify_connected": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    
    user_doc.pop("password_hash", None)
    user_doc.pop("_id", None)
    return {"user": user_doc, "access_token": access_token}

@api_router.post("/auth/login")
async def login(response: Response, input: UserLogin):
    email = input.email.lower()
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(input.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(user["user_id"], email)
    refresh_token = create_refresh_token(user["user_id"])
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    
    user.pop("password_hash", None)
    return {"user": user, "access_token": access_token}

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out successfully"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    return user

# Google OAuth Session Handler
@api_router.post("/auth/session")
async def handle_google_session(request: Request, response: Response):
    body = await request.json()
    session_id = body.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    
    async with httpx.AsyncClient() as client_http:
        resp = await client_http.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": session_id}
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid session")
        google_data = resp.json()
    
    email = google_data.get("email", "").lower()
    name = google_data.get("name", "")
    picture = google_data.get("picture", "")
    session_token = google_data.get("session_token")
    
    # Check if user exists
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "picture": picture,
            "role": "user",
            "store_name": None,
            "store_url": None,
            "shopify_connected": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(user)
    else:
        user_id = user["user_id"]
        await db.users.update_one({"user_id": user_id}, {"$set": {"name": name, "picture": picture}})
        user["name"] = name
        user["picture"] = picture
    
    # Store session
    await db.user_sessions.insert_one({
        "user_id": user_id,
        "session_token": session_token,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "created_at": datetime.now(timezone.utc)
    })
    
    response.set_cookie(key="session_token", value=session_token, httponly=True, secure=True, samesite="none", max_age=604800, path="/")
    
    user.pop("password_hash", None)
    user.pop("_id", None)
    return user

# ======================= STORE SETTINGS =======================

@api_router.put("/store/settings")
async def update_store_settings(settings: StoreSettings, request: Request):
    user = await get_current_user(request)
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {
            "store_name": settings.store_name,
            "store_url": settings.store_url,
            "currency": settings.currency,
            "timezone": settings.timezone
        }}
    )
    return {"message": "Settings updated"}

@api_router.get("/store/settings")
async def get_store_settings(request: Request):
    user = await get_current_user(request)
    return {
        "store_name": user.get("store_name", ""),
        "store_url": user.get("store_url", ""),
        "currency": user.get("currency", "USD"),
        "timezone": user.get("timezone", "UTC"),
        "shopify_connected": user.get("shopify_connected", False)
    }

# ======================= ABANDONED CARTS =======================

@api_router.get("/carts")
async def get_abandoned_carts(request: Request, status: Optional[str] = None, limit: int = 50):
    user = await get_current_user(request)
    query = {"user_id": user["user_id"]}
    if status:
        query["status"] = status
    carts = await db.abandoned_carts.find(query, {"_id": 0}).sort("created_at", -1).limit(limit).to_list(limit)
    return carts

@api_router.post("/carts")
async def create_abandoned_cart(cart: AbandonedCartCreate, request: Request):
    user = await get_current_user(request)
    cart_id = f"cart_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    cart_doc = {
        "cart_id": cart_id,
        "user_id": user["user_id"],
        "customer_email": cart.customer_email,
        "customer_name": cart.customer_name,
        "items": cart.items,
        "total_value": cart.total_value,
        "status": "pending",
        "created_at": now,
        "updated_at": now,
        "recovery_attempts": 0,
        "recovered_at": None
    }
    await db.abandoned_carts.insert_one(cart_doc)
    cart_doc.pop("_id", None)
    return cart_doc

@api_router.put("/carts/{cart_id}/status")
async def update_cart_status(cart_id: str, request: Request):
    user = await get_current_user(request)
    body = await request.json()
    status = body.get("status")
    if status not in ["pending", "recovered", "lost"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    update_data = {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
    if status == "recovered":
        update_data["recovered_at"] = datetime.now(timezone.utc).isoformat()
    
    result = await db.abandoned_carts.update_one(
        {"cart_id": cart_id, "user_id": user["user_id"]},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Cart not found")
    return {"message": "Status updated"}

@api_router.delete("/carts/{cart_id}")
async def delete_cart(cart_id: str, request: Request):
    user = await get_current_user(request)
    result = await db.abandoned_carts.delete_one({"cart_id": cart_id, "user_id": user["user_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Cart not found")
    return {"message": "Cart deleted"}

# ======================= EMAIL CAMPAIGNS =======================

@api_router.get("/campaigns")
async def get_campaigns(request: Request):
    user = await get_current_user(request)
    campaigns = await db.email_campaigns.find({"user_id": user["user_id"]}, {"_id": 0}).to_list(100)
    return campaigns

@api_router.post("/campaigns")
async def create_campaign(campaign: EmailCampaignCreate, request: Request):
    user = await get_current_user(request)
    campaign_id = f"camp_{uuid.uuid4().hex[:12]}"
    campaign_doc = {
        "campaign_id": campaign_id,
        "user_id": user["user_id"],
        "name": campaign.name,
        "subject": campaign.subject,
        "template": campaign.template,
        "delay_hours": campaign.delay_hours,
        "discount_code": campaign.discount_code,
        "discount_percent": campaign.discount_percent,
        "is_active": campaign.is_active,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "emails_sent": 0,
        "emails_opened": 0,
        "conversions": 0
    }
    await db.email_campaigns.insert_one(campaign_doc)
    campaign_doc.pop("_id", None)
    return campaign_doc

@api_router.put("/campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, campaign: EmailCampaignCreate, request: Request):
    user = await get_current_user(request)
    update_data = campaign.model_dump()
    result = await db.email_campaigns.update_one(
        {"campaign_id": campaign_id, "user_id": user["user_id"]},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"message": "Campaign updated"}

@api_router.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str, request: Request):
    user = await get_current_user(request)
    result = await db.email_campaigns.delete_one({"campaign_id": campaign_id, "user_id": user["user_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"message": "Campaign deleted"}

# ======================= EXIT POPUPS =======================

@api_router.get("/popups")
async def get_popups(request: Request):
    user = await get_current_user(request)
    popups = await db.popup_configs.find({"user_id": user["user_id"]}, {"_id": 0}).to_list(100)
    return popups

@api_router.post("/popups")
async def create_popup(popup: PopupConfigCreate, request: Request):
    user = await get_current_user(request)
    popup_id = f"popup_{uuid.uuid4().hex[:12]}"
    popup_doc = {
        "popup_id": popup_id,
        "user_id": user["user_id"],
        **popup.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "impressions": 0,
        "conversions": 0
    }
    await db.popup_configs.insert_one(popup_doc)
    popup_doc.pop("_id", None)
    return popup_doc

@api_router.put("/popups/{popup_id}")
async def update_popup(popup_id: str, popup: PopupConfigCreate, request: Request):
    user = await get_current_user(request)
    update_data = popup.model_dump()
    result = await db.popup_configs.update_one(
        {"popup_id": popup_id, "user_id": user["user_id"]},
        {"$set": update_data}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Popup not found")
    return {"message": "Popup updated"}

@api_router.delete("/popups/{popup_id}")
async def delete_popup(popup_id: str, request: Request):
    user = await get_current_user(request)
    result = await db.popup_configs.delete_one({"popup_id": popup_id, "user_id": user["user_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Popup not found")
    return {"message": "Popup deleted"}

# ======================= ANALYTICS =======================

@api_router.get("/analytics/overview")
async def get_analytics_overview(request: Request):
    user = await get_current_user(request)
    user_id = user["user_id"]
    
    # Get cart stats
    total_carts = await db.abandoned_carts.count_documents({"user_id": user_id})
    pending_carts = await db.abandoned_carts.count_documents({"user_id": user_id, "status": "pending"})
    recovered_carts = await db.abandoned_carts.count_documents({"user_id": user_id, "status": "recovered"})
    lost_carts = await db.abandoned_carts.count_documents({"user_id": user_id, "status": "lost"})
    
    # Calculate revenue
    recovered_pipeline = [
        {"$match": {"user_id": user_id, "status": "recovered"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_value"}}}
    ]
    recovered_result = await db.abandoned_carts.aggregate(recovered_pipeline).to_list(1)
    recovered_revenue = recovered_result[0]["total"] if recovered_result else 0
    
    lost_pipeline = [
        {"$match": {"user_id": user_id, "status": "lost"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_value"}}}
    ]
    lost_result = await db.abandoned_carts.aggregate(lost_pipeline).to_list(1)
    lost_revenue = lost_result[0]["total"] if lost_result else 0
    
    pending_pipeline = [
        {"$match": {"user_id": user_id, "status": "pending"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_value"}}}
    ]
    pending_result = await db.abandoned_carts.aggregate(pending_pipeline).to_list(1)
    pending_revenue = pending_result[0]["total"] if pending_result else 0
    
    # Campaign stats
    campaign_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": None,
            "emails_sent": {"$sum": "$emails_sent"},
            "emails_opened": {"$sum": "$emails_opened"},
            "conversions": {"$sum": "$conversions"}
        }}
    ]
    campaign_result = await db.email_campaigns.aggregate(campaign_pipeline).to_list(1)
    campaign_stats = campaign_result[0] if campaign_result else {"emails_sent": 0, "emails_opened": 0, "conversions": 0}
    
    conversion_rate = (recovered_carts / total_carts * 100) if total_carts > 0 else 0
    
    return {
        "total_carts": total_carts,
        "pending_carts": pending_carts,
        "recovered_carts": recovered_carts,
        "lost_carts": lost_carts,
        "recovered_revenue": recovered_revenue,
        "lost_revenue": lost_revenue,
        "pending_revenue": pending_revenue,
        "conversion_rate": round(conversion_rate, 1),
        "emails_sent": campaign_stats.get("emails_sent", 0),
        "emails_opened": campaign_stats.get("emails_opened", 0),
        "email_conversions": campaign_stats.get("conversions", 0)
    }

@api_router.get("/analytics/chart")
async def get_analytics_chart(request: Request, days: int = 7):
    user = await get_current_user(request)
    user_id = user["user_id"]
    
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    pipeline = [
        {"$match": {
            "user_id": user_id,
            "created_at": {"$gte": start_date.isoformat()}
        }},
        {"$addFields": {
            "date": {"$substr": ["$created_at", 0, 10]}
        }},
        {"$group": {
            "_id": {"date": "$date", "status": "$status"},
            "count": {"$sum": 1},
            "value": {"$sum": "$total_value"}
        }},
        {"$sort": {"_id.date": 1}}
    ]
    
    results = await db.abandoned_carts.aggregate(pipeline).to_list(1000)
    
    # Process into chart data
    chart_data = {}
    for r in results:
        date = r["_id"]["date"]
        status = r["_id"]["status"]
        if date not in chart_data:
            chart_data[date] = {"date": date, "abandoned": 0, "recovered": 0, "lost": 0, "revenue": 0}
        if status == "pending":
            chart_data[date]["abandoned"] += r["count"]
        elif status == "recovered":
            chart_data[date]["recovered"] += r["count"]
            chart_data[date]["revenue"] += r["value"]
        elif status == "lost":
            chart_data[date]["lost"] += r["count"]
    
    return list(chart_data.values())

# ======================= AI INSIGHTS =======================

@api_router.post("/ai/insights")
async def get_ai_insights(request: Request, insight_request: AIInsightRequest):
    user = await get_current_user(request)
    user_id = user["user_id"]
    
    # Gather analytics data directly
    total_carts = await db.abandoned_carts.count_documents({"user_id": user_id})
    pending_carts = await db.abandoned_carts.count_documents({"user_id": user_id, "status": "pending"})
    recovered_carts = await db.abandoned_carts.count_documents({"user_id": user_id, "status": "recovered"})
    lost_carts = await db.abandoned_carts.count_documents({"user_id": user_id, "status": "lost"})
    
    # Calculate revenue
    recovered_pipeline = [
        {"$match": {"user_id": user_id, "status": "recovered"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_value"}}}
    ]
    recovered_result = await db.abandoned_carts.aggregate(recovered_pipeline).to_list(1)
    recovered_revenue = recovered_result[0]["total"] if recovered_result else 0
    
    lost_pipeline = [
        {"$match": {"user_id": user_id, "status": "lost"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_value"}}}
    ]
    lost_result = await db.abandoned_carts.aggregate(lost_pipeline).to_list(1)
    lost_revenue = lost_result[0]["total"] if lost_result else 0
    
    pending_pipeline = [
        {"$match": {"user_id": user_id, "status": "pending"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_value"}}}
    ]
    pending_result = await db.abandoned_carts.aggregate(pending_pipeline).to_list(1)
    pending_revenue = pending_result[0]["total"] if pending_result else 0
    
    # Campaign stats
    campaign_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": None,
            "emails_sent": {"$sum": "$emails_sent"},
            "emails_opened": {"$sum": "$emails_opened"},
            "conversions": {"$sum": "$conversions"}
        }}
    ]
    campaign_result = await db.email_campaigns.aggregate(campaign_pipeline).to_list(1)
    campaign_stats = campaign_result[0] if campaign_result else {"emails_sent": 0, "emails_opened": 0, "conversions": 0}
    
    conversion_rate = (recovered_carts / total_carts * 100) if total_carts > 0 else 0
    
    analytics = {
        "total_carts": total_carts,
        "pending_carts": pending_carts,
        "recovered_carts": recovered_carts,
        "lost_carts": lost_carts,
        "recovered_revenue": recovered_revenue,
        "lost_revenue": lost_revenue,
        "pending_revenue": pending_revenue,
        "conversion_rate": round(conversion_rate, 1),
        "emails_sent": campaign_stats.get("emails_sent", 0),
        "emails_opened": campaign_stats.get("emails_opened", 0),
        "email_conversions": campaign_stats.get("conversions", 0)
    }
    
    # Get recent carts for pattern analysis
    recent_carts = await db.abandoned_carts.find(
        {"user_id": user_id},
        {"_id": 0, "items": 1, "total_value": 1, "status": 1}
    ).sort("created_at", -1).limit(20).to_list(20)
    
    # Build context for AI
    context = f"""
    Store Analytics:
    - Total abandoned carts: {analytics['total_carts']}
    - Recovered carts: {analytics['recovered_carts']}
    - Lost carts: {analytics['lost_carts']}
    - Recovery rate: {analytics['conversion_rate']}%
    - Recovered revenue: ${analytics['recovered_revenue']:.2f}
    - Lost revenue: ${analytics['lost_revenue']:.2f}
    - Pending revenue at risk: ${analytics['pending_revenue']:.2f}
    - Emails sent: {analytics['emails_sent']}
    - Email open rate: {(analytics['emails_opened'] / analytics['emails_sent'] * 100) if analytics['emails_sent'] > 0 else 0:.1f}%
    
    Recent cart patterns:
    {recent_carts[:5]}
    """
    
    # Check for API key
    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        # Return static insights if no API key
        return {
            "insights": [
                {
                    "type": "recovery_rate",
                    "title": "Recovery Performance",
                    "message": f"Your cart recovery rate is {analytics['conversion_rate']}%. " + 
                              ("Great job! Keep optimizing your email campaigns." if analytics['conversion_rate'] > 20 
                               else "Consider sending follow-up emails sooner and testing different discount offers."),
                    "priority": "high" if analytics['conversion_rate'] < 15 else "medium"
                },
                {
                    "type": "revenue",
                    "title": "Revenue at Risk",
                    "message": f"You have ${analytics['pending_revenue']:.2f} in pending carts. Focus on recovering these before they expire.",
                    "priority": "high" if analytics['pending_revenue'] > 500 else "medium"
                },
                {
                    "type": "email",
                    "title": "Email Campaign Tip",
                    "message": "Try personalizing your email subject lines with the customer's name and cart items for higher open rates.",
                    "priority": "low"
                }
            ],
            "ai_powered": False
        }
    
    # Use AI for insights
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        
        system_message = """You are an e-commerce analytics expert. Analyze the store data and provide 3-4 actionable insights.
        Each insight should have a type (recovery_rate, revenue, email, checkout, pricing), title, message, and priority (high/medium/low).
        Focus on specific, actionable recommendations based on the data.
        Return your response as a JSON array of insights."""
        
        chat = LlmChat(
            api_key=api_key,
            session_id=f"insights_{user_id}_{datetime.now().timestamp()}",
            system_message=system_message
        ).with_model("openai", "gpt-5.2")
        
        user_message = UserMessage(text=f"{context}\n\nProvide actionable insights for this e-commerce store.")
        response = await chat.send_message(user_message)
        
        # Parse AI response
        import json
        try:
            # Try to extract JSON from response
            if "[" in response and "]" in response:
                start = response.find("[")
                end = response.rfind("]") + 1
                insights = json.loads(response[start:end])
            else:
                insights = json.loads(response)
        except:
            insights = [{"type": "ai", "title": "AI Analysis", "message": response, "priority": "medium"}]
        
        return {"insights": insights, "ai_powered": True}
        
    except Exception as e:
        logger.error(f"AI insights error: {e}")
        return {
            "insights": [
                {
                    "type": "error",
                    "title": "AI Insights Unavailable",
                    "message": "Unable to generate AI insights. Basic analytics are still available.",
                    "priority": "low"
                }
            ],
            "ai_powered": False
        }

@api_router.post("/ai/email-suggestion")
async def get_email_suggestion(request: Request):
    user = await get_current_user(request)
    body = await request.json()
    cart_value = body.get("cart_value", 0)
    product_names = body.get("product_names", [])
    
    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        # Return template if no API key
        return {
            "subject": "Did you forget something? Complete your order!",
            "template": f"""Hi {{{{customer_name}}}},

We noticed you left some items in your cart. Your {{{{product_names}}}} are waiting for you!

Complete your purchase now and get {{{{discount_percent}}}}% off with code: {{{{discount_code}}}}

Total: ${{{{cart_total}}}}

[Complete Purchase]

Thanks,
{{{{store_name}}}}""",
            "ai_powered": False
        }
    
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        
        system_message = """You are an expert email copywriter for e-commerce. Write a compelling abandoned cart recovery email.
        Use these template variables: {{customer_name}}, {{product_names}}, {{discount_percent}}, {{discount_code}}, {{cart_total}}, {{store_name}}
        Keep it short, friendly, and focused on urgency without being pushy.
        Return JSON with 'subject' and 'template' fields."""
        
        chat = LlmChat(
            api_key=api_key,
            session_id=f"email_{user['user_id']}_{datetime.now().timestamp()}",
            system_message=system_message
        ).with_model("openai", "gpt-5.2")
        
        prompt = f"Write an abandoned cart email for products: {', '.join(product_names) if product_names else 'various items'}. Cart value: ${cart_value}"
        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        import json
        try:
            if "{" in response:
                start = response.find("{")
                end = response.rfind("}") + 1
                result = json.loads(response[start:end])
                return {**result, "ai_powered": True}
        except:
            pass
        
        return {"subject": "Complete your purchase!", "template": response, "ai_powered": True}
        
    except Exception as e:
        logger.error(f"AI email suggestion error: {e}")
        return {
            "subject": "Complete your order today!",
            "template": "Hi {{customer_name}}, your cart is waiting!",
            "ai_powered": False
        }

# ======================= SHOPIFY DEMO WEBHOOK =======================

@api_router.post("/webhook/shopify/cart")
async def shopify_cart_webhook(request: Request):
    """Demo webhook endpoint for Shopify cart events"""
    body = await request.json()
    
    # In demo mode, we accept any cart data
    # In production, this would verify Shopify webhook signature
    
    logger.info(f"Received Shopify webhook: {body}")
    
    return {"status": "received", "demo_mode": True}

@api_router.post("/demo/generate-carts")
async def generate_demo_carts(request: Request):
    """Generate demo abandoned carts for testing"""
    user = await get_current_user(request)
    
    demo_products = [
        {"name": "Wireless Headphones", "price": 79.99, "quantity": 1, "image": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=200"},
        {"name": "Smart Watch", "price": 199.99, "quantity": 1, "image": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=200"},
        {"name": "Running Shoes", "price": 129.99, "quantity": 1, "image": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=200"},
        {"name": "Laptop Stand", "price": 49.99, "quantity": 2, "image": "https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?w=200"},
        {"name": "Mechanical Keyboard", "price": 149.99, "quantity": 1, "image": "https://images.unsplash.com/photo-1511467687858-23d96c32e4ae?w=200"},
    ]
    
    demo_customers = [
        {"email": "john.doe@example.com", "name": "John Doe"},
        {"email": "jane.smith@example.com", "name": "Jane Smith"},
        {"email": "mike.wilson@example.com", "name": "Mike Wilson"},
        {"email": "sarah.johnson@example.com", "name": "Sarah Johnson"},
        {"email": "alex.brown@example.com", "name": "Alex Brown"},
    ]
    
    import random
    created_carts = []
    
    for i in range(5):
        items = random.sample(demo_products, random.randint(1, 3))
        total = sum(item["price"] * item["quantity"] for item in items)
        customer = random.choice(demo_customers)
        status = random.choice(["pending", "pending", "pending", "recovered", "lost"])
        
        cart_id = f"cart_{uuid.uuid4().hex[:12]}"
        days_ago = random.randint(0, 7)
        created_at = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        
        cart_doc = {
            "cart_id": cart_id,
            "user_id": user["user_id"],
            "customer_email": customer["email"],
            "customer_name": customer["name"],
            "items": items,
            "total_value": round(total, 2),
            "status": status,
            "created_at": created_at,
            "updated_at": created_at,
            "recovery_attempts": random.randint(0, 3),
            "recovered_at": created_at if status == "recovered" else None
        }
        
        await db.abandoned_carts.insert_one(cart_doc)
        cart_doc.pop("_id", None)
        created_carts.append(cart_doc)
    
    return {"message": f"Created {len(created_carts)} demo carts", "carts": created_carts}

# ======================= HEALTH CHECK =======================

@api_router.get("/")
async def root():
    return {"message": "CartReclaim API", "version": "1.0.0"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# Include the router in the main app
app.include_router(api_router)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event - create indexes
@app.on_event("startup")
async def startup_event():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("user_id", unique=True)
    await db.abandoned_carts.create_index("user_id")
    await db.abandoned_carts.create_index("cart_id", unique=True)
    await db.email_campaigns.create_index("user_id")
    await db.popup_configs.create_index("user_id")
    await db.user_sessions.create_index("session_token")
    logger.info("Database indexes created")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
