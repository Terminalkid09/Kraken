import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.main import app
from app.db.session import Base, get_db
from app.models.models import User
from app.core.security import hash_password
from app.core.config import settings

TEST_DB = "sqlite+aiosqlite:///:memory:"
engine = create_async_engine(TEST_DB, echo=False)
TestSession = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

INTERNAL_KEY = settings.INTERNAL_API_KEY


async def override_db():
    async with TestSession() as s:
        yield s

app.dependency_overrides[get_db] = override_db


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_token(client):
    async with TestSession() as db:
        db.add(User(username="admin", hashed_password=hash_password("adminpass"),
                    is_admin=True, is_active=True))
        await db.commit()
    res = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpass"})
    return res.json()["access_token"]


def auth(token): return {"Authorization": f"Bearer {token}"}
def ikey(): return {"X-Internal-API-Key": INTERNAL_KEY}


# ── Health ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    res = await client.get("/health")
    assert res.status_code == 200 and res.json()["status"] == "ok"


# ── Auth ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(client):
    async with TestSession() as db:
        db.add(User(username="u1", hashed_password=hash_password("pass1"), is_active=True))
        await db.commit()
    res = await client.post("/api/v1/auth/login", json={"username": "u1", "password": "pass1"})
    assert res.status_code == 200 and "access_token" in res.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    async with TestSession() as db:
        db.add(User(username="u2", hashed_password=hash_password("right"), is_active=True))
        await db.commit()
    res = await client.post("/api/v1/auth/login", json={"username": "u2", "password": "wrong"})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_register_success(client):
    res = await client.post("/api/v1/auth/register",
                             json={"username": "newuser", "password": "password123"})
    assert res.status_code == 201 and res.json()["username"] == "newuser"


@pytest.mark.asyncio
async def test_register_duplicate(client):
    await client.post("/api/v1/auth/register", json={"username": "dup", "password": "pass1234"})
    res = await client.post("/api/v1/auth/register", json={"username": "dup", "password": "pass5678"})
    assert res.status_code == 400


# ── Events ingest ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_requires_api_key(client):
    res = await client.post("/api/v1/events/ingest", json={
        "sensor_type": "ssh", "attacker_ip": "1.2.3.4",
        "attacker_port": 1234, "sensor_port": 2222, "session_id": "no-key-001",
    })
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_ingest_success(client):
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        res = await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "ssh", "attacker_ip": "5.6.7.8",
            "attacker_port": 55000, "sensor_port": 2222, "session_id": "ingest-001",
            "username": "root", "password": "root",
        })
    assert res.status_code == 201
    data = res.json()
    assert data["attacker_ip"] == "5.6.7.8" and data["sensor_type"] == "ssh"


# ── Events list ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_events_requires_auth(client):
    assert (await client.get("/api/v1/events/")).status_code == 401


@pytest.mark.asyncio
async def test_list_events_authenticated(client, auth_token):
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "http", "attacker_ip": "9.9.9.9",
            "attacker_port": 80, "sensor_port": 8080, "session_id": "list-001",
        })
    res = await client.get("/api/v1/events/", headers=auth(auth_token))
    assert res.status_code == 200 and isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_list_events_sensor_filter(client, auth_token):
    for i, sensor in enumerate(["ssh", "http"]):
        with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
            await client.post("/api/v1/events/ingest", headers=ikey(), json={
                "sensor_type": sensor, "attacker_ip": f"10.0.{i}.1",
                "attacker_port": 1000 + i, "sensor_port": 2000 + i,
                "session_id": f"filter-sensor-{i}",
            })
    res = await client.get("/api/v1/events/?sensor_type=ssh", headers=auth(auth_token))
    assert all(e["sensor_type"] == "ssh" for e in res.json())


# ── Stats ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_requires_auth(client):
    assert (await client.get("/api/v1/events/stats")).status_code == 401


@pytest.mark.asyncio
async def test_stats_returns_expected_keys(client, auth_token):
    res = await client.get("/api/v1/events/stats", headers=auth(auth_token))
    assert res.status_code == 200
    data = res.json()
    for key in ["total_attacks", "attacks_today", "unique_ips", "top_countries",
                "top_sensors", "attacks_over_time", "geo_points"]:
        assert key in data


# ── Export ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_csv(client, auth_token):
    res = await client.get("/api/v1/export/csv", headers=auth(auth_token))
    assert res.status_code == 200 and "text/csv" in res.headers["content-type"]


@pytest.mark.asyncio
async def test_export_json(client, auth_token):
    res = await client.get("/api/v1/export/json", headers=auth(auth_token))
    assert res.status_code == 200 and "application/json" in res.headers["content-type"]


@pytest.mark.asyncio
async def test_export_pdf(client, auth_token):
    res = await client.get("/api/v1/export/pdf", headers=auth(auth_token))
    assert res.status_code == 200 and "application/pdf" in res.headers["content-type"]


# ── Containers ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_containers_requires_auth(client):
    assert (await client.get("/api/v1/containers/active")).status_code == 401


@pytest.mark.asyncio
async def test_containers_list(client, auth_token):
    res = await client.get("/api/v1/containers/active", headers=auth(auth_token))
    assert res.status_code == 200 and isinstance(res.json(), list)
