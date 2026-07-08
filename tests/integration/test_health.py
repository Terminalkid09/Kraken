import pytest
from httpx import AsyncClient


class TestHealth:
    async def test_health_endpoint(self, client: AsyncClient):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "degraded")
        assert "checks" in data

    async def test_health_database_unhealthy(self, client: AsyncClient, monkeypatch):
        from app.db.session import get_db
        from sqlalchemy.exc import OperationalError

        async def failing_db():
            raise OperationalError("Connection refused", None, None)

        from app.main import app
        app.dependency_overrides[get_db] = failing_db
        try:
            response = await client.get("/api/v1/health")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"
        finally:
            app.dependency_overrides.clear()

    async def test_metrics_endpoint(self, client: AsyncClient):
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "kraken_http_requests_total" in response.text
        assert "kraken_http_request_duration_seconds" in response.text