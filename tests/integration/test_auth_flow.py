import pytest
from httpx import AsyncClient


class TestAuthFlow:
    async def test_register_success(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/register", json={
            "username": "newuser",
            "password": "securepass123",
            "is_admin": False
        })
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["is_admin"] is False
        assert "id" in data

    async def test_register_duplicate_username(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/register", json={
            "username": test_user.username,
            "password": "anotherpass123",
            "is_admin": False
        })
        assert response.status_code == 400
        assert "already taken" in response.json()["detail"]

    async def test_login_success(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpass123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "kraken_token" in response.cookies

    async def test_login_invalid_credentials(self, client: AsyncClient, test_user):
        response = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient):
        response = await client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "anypassword"
        })
        assert response.status_code == 401

    async def test_cookie_auth_on_protected_route(self, client: AsyncClient, test_user):
        login_resp = await client.post("/api/v1/auth/login", json={
            "username": test_user.username,
            "password": "testpass123"
        })
        assert login_resp.status_code == 200
        cookie = login_resp.cookies.get("kraken_token")
        assert cookie is not None

        client.cookies.set("kraken_token", cookie)
        response = await client.get("/api/v1/events/")
        assert response.status_code == 200

    async def test_bearer_token_auth_on_protected_route(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/events/", headers=auth_headers)
        assert response.status_code == 200

    async def test_unauthorized_without_token(self, client: AsyncClient):
        response = await client.get("/api/v1/events/")
        assert response.status_code == 401

    async def test_rate_limit_on_login(self, client: AsyncClient):
        for _ in range(12):
            await client.post("/api/v1/auth/login", json={
                "username": "nonexistent",
                "password": "wrong"
            })
        response = await client.post("/api/v1/auth/login", json={
            "username": "nonexistent",
            "password": "wrong"
        })
        assert response.status_code == 429