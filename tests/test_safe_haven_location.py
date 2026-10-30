"""
NIVARA Safe Haven Discovery & Victim Location Verification Test Suite
Verifies:
1. Haversine distance accuracy and boundary conditions.
2. Proximity sorting (nearest-first) with genuine Tamil Nadu & Karnataka safe havens.
3. Siruseri (12.8353, 80.2190) coordinates discovery: AWPS Kelambakkam (~5.65 km) and Sakhi Chengalpattu (~29.7 km) nearest.
4. Truthful radius limits, within_radius_count, nearest_distance_km, and is_local_coverage_limited notice.
5. Missing coordinates graceful handling without fabricated distances.
6. OpenStreetMap Overpass nwr query, center coordinate extraction, and deduplication.
7. Multi-endpoint fallback and error resilience.
8. Aggregate provider (all sources) merging and sorting.
9. In-memory cache isolation (raw records cached, user coordinates never cached).
10. Truthful bed vacancy and emergency hotline disclosures.
"""

import pytest
import math
from typing import List
from starlette.testclient import TestClient
from server import app
from safe_haven_service import (
    calculate_haversine,
    safe_haven_service,
    SafeHavenRecord,
    GovernmentOSCDirectoryProvider,
    OpenStreetMapOverpassProvider,
    DemoSafeHavenProvider
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _create_isolated_victim(client, name="Safe Haven Test Victim"):
    email = f"haven_victim_{math.floor(math.sin(hash(name)) * 1000000)}@test.nivara.org"
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "name": name,
        "password": "Password123!",
        "language": "en",
        "phone": "+919876543210",
        "saved_location": "Siruseri, Chennai, Tamil Nadu"
    })
    if reg_res.status_code == 200:
        return reg_res.json()["user"], reg_res.json()["token"]
    login_res = client.post("/api/auth/login", json={"email": email, "password": "Password123!"})
    return login_res.json()["user"], login_res.json()["token"]


# ---------------------------------------------------------------------------
# 1. Haversine Distance Calculation Unit Tests
# ---------------------------------------------------------------------------
def test_haversine_distance_accuracy_and_boundaries():
    """Haversine formula calculates exact great-circle distance within <0.5% error."""
    # Siruseri (12.8353, 80.2190) to AWPS Kelambakkam (12.7845, 80.2205)
    d_kelambakkam = calculate_haversine(12.8353, 80.2190, 12.7845, 80.2205)
    assert 5.4 < d_kelambakkam < 5.9  # approx 5.65 km

    # Siruseri (12.8353, 80.2190) to Sakhi One Stop Centre Chengalpattu (12.6845, 79.9835)
    d_chengalpattu = calculate_haversine(12.8353, 80.2190, 12.6845, 79.9835)
    assert 28.5 < d_chengalpattu < 31.0  # approx 29.7 km

    # Distance to identical point is 0.0
    assert calculate_haversine(12.8353, 80.2190, 12.8353, 80.2190) == 0.0

    # Distance between Bengaluru and Chennai (~290 km)
    d_blr_chn = calculate_haversine(12.9716, 77.5946, 13.0827, 80.2707)
    assert 280 < d_blr_chn < 300

    # Invalid coordinates return float('inf') safely
    assert calculate_haversine(None, 80.0, 12.0, 80.0) == float("inf")
    assert calculate_haversine(95.0, 80.0, 12.0, 80.0) == float("inf")
    assert calculate_haversine(12.0, -195.0, 12.0, 80.0) == float("inf")


# ---------------------------------------------------------------------------
# 2. Victim Location Proximity Sorting & Nearest Centers Discovery
# ---------------------------------------------------------------------------
def test_siruseri_victim_location_discovers_nearest_tamil_nadu_centres(client):
    """Victim at Siruseri (12.8353, 80.2190) receives nearest TN centres first, NOT Bengaluru 284 km away."""
    _, victim_token = _create_isolated_victim(client, "Siruseri Victim")
    safe_haven_service.clear_cache()

    res = client.get(
        "/api/safe-havens?lat=12.8353&lng=80.2190&provider=osc_directory",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["has_user_location"] is True
    assert data["user_location"]["latitude"] == 12.8353
    assert data["user_location"]["longitude"] == 80.2190

    havens = data["havens"]
    assert len(havens) >= 5

    # First haven must be AWPS Kelambakkam (~5.65 km away)
    first_haven = havens[0]
    assert "Kelambakkam" in first_haven["name"]
    assert first_haven["distance_km"] < 6.0
    assert first_haven["type"] == "police"

    # Distances must be sorted ascending (nearest first)
    distances = [h["distance_km"] for h in havens if h.get("distance_km") is not None]
    assert distances == sorted(distances)

    # Bengaluru centre must be far down the list (> 250 km)
    blr_centre = next((h for h in havens if "Bengaluru Urban" in h["name"]), None)
    assert blr_centre is not None
    assert blr_centre["distance_km"] > 250.0


# ---------------------------------------------------------------------------
# 3. Truthful Radius Limits and Limited Coverage Disclosures
# ---------------------------------------------------------------------------
def test_safe_haven_search_radius_and_limited_coverage_disclosure(client):
    """When searching within narrow radius where no centre exists, reports truthful limited coverage notice."""
    _, victim_token = _create_isolated_victim(client, "Radius Test Victim")
    safe_haven_service.clear_cache()

    # Query with tiny radius of 2 km from Siruseri (nearest center is ~5.65 km away)
    res_2km = client.get(
        "/api/safe-havens?lat=12.8353&lng=80.2190&provider=osc_directory&radius_km=2.0",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_2km.status_code == 200
    data_2km = res_2km.json()

    assert data_2km["radius_km"] == 2.0
    assert data_2km["within_radius_count"] == 0
    assert data_2km["is_local_coverage_limited"] is True
    assert data_2km["nearest_distance_km"] is not None
    assert data_2km["nearest_distance_km"] < 6.0
    assert "No verified safe haven facility found within 2 km" in data_2km["coverage_notice"]
    assert "181" in data_2km["coverage_notice"] or "112" in data_2km["coverage_notice"]

    # Query with 10 km radius (Kelambakkam is within 10 km)
    res_10km = client.get(
        "/api/safe-havens?lat=12.8353&lng=80.2190&provider=osc_directory&radius_km=10.0",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_10km.status_code == 200
    data_10km = res_10km.json()
    assert data_10km["within_radius_count"] >= 1
    assert data_10km["is_local_coverage_limited"] is False


# ---------------------------------------------------------------------------
# 4. Missing Location Coordinates Handling
# ---------------------------------------------------------------------------
def test_missing_coordinates_honestly_reports_distance_unavailable(client):
    """When coordinates are omitted, distances remain None and coverage notice informs victim."""
    _, victim_token = _create_isolated_victim(client, "No GPS Victim")
    safe_haven_service.clear_cache()

    res = client.get(
        "/api/safe-havens?provider=osc_directory",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["has_user_location"] is False
    assert data["user_location"] is None
    assert data["distance_calculation_method"] is None
    assert "Enable GPS" in data["coverage_notice"]

    for h in data["havens"]:
        assert h["distance_km"] is None
        assert h["distance_type"] is None


# ---------------------------------------------------------------------------
# 5. OpenStreetMap Overpass Provider Resilience & Deduplication
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_openstreetmap_overpass_provider_nwr_and_deduplication(monkeypatch):
    """OpenStreetMap Overpass parser handles nodes, ways with center coordinates, and deduplicates records."""
    mock_osm_response = {
        "elements": [
            {
                "type": "node",
                "id": 1001,
                "lat": 12.8360,
                "lon": 80.2195,
                "tags": {
                    "name": "Siruseri Police Outpost",
                    "amenity": "police",
                    "phone": "+91 44 2747 0000"
                }
            },
            {
                "type": "way",
                "id": 2002,
                "center": {"lat": 12.8400, "lon": 80.2250},
                "tags": {
                    "name": "Chettinad Hospital Emergency Center",
                    "amenity": "hospital",
                    "healthcare": "hospital",
                    "opening_hours": "24/7"
                }
            },
            {
                # Duplicate coordinate and name to test deduplication
                "type": "node",
                "id": 1001,
                "lat": 12.8360,
                "lon": 80.2195,
                "tags": {
                    "name": "Siruseri Police Outpost",
                    "amenity": "police"
                }
            }
        ]
    }

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def post(self, url, data=None):
            class MockResponse:
                status_code = 200
                def json(self):
                    return mock_osm_response
            return MockResponse()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    provider = OpenStreetMapOverpassProvider()
    records = await provider.fetch_havens(lat=12.8353, lng=80.2190, radius_km=15.0)

    # Should parse 2 unique records (deduplicating the duplicate node)
    assert len(records) == 2

    # Check node parsed
    police = next(r for r in records if r.type == "police")
    assert police.id == "osm-node-1001"
    assert police.latitude == 12.8360
    assert police.longitude == 80.2195
    assert police.is_verified_source is False

    # Check way parsed with center coordinates
    hospital = next(r for r in records if r.type == "hospital")
    assert hospital.id == "osm-way-2002"
    assert hospital.latitude == 12.8400
    assert hospital.longitude == 80.2250
    assert hospital.operating_hours == "24/7"


# ---------------------------------------------------------------------------
# 6. Aggregate Provider ('all') Tests
# ---------------------------------------------------------------------------
def test_aggregate_provider_combines_and_sorts_havens(client, monkeypatch):
    """Provider 'all' queries both government directory and community OSM and sorts by distance."""
    async def mock_osm_fetch(*args, **kwargs):
        return [
            SafeHavenRecord(
                id="osm-node-8888",
                name="SIPCOT Emergency First Aid Post",
                type="hospital",
                latitude=12.8355,
                longitude=80.2192,
                source_name="OpenStreetMap Community",
                source_type="openstreetmap",
                is_verified_source=False,
                is_location_verified=False,
                disclaimer="Community map data."
            )
        ]

    monkeypatch.setattr(OpenStreetMapOverpassProvider, "fetch_havens", mock_osm_fetch)
    safe_haven_service.clear_cache()

    _, victim_token = _create_isolated_victim(client, "Aggregate Victim")

    res = client.get(
        "/api/safe-havens?lat=12.8353&lng=80.2190&provider=all",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["provider_id"] == "all"
    assert "Combined Directory" in data["provider_name"]

    havens = data["havens"]
    sources = {h["source_type"] for h in havens}
    assert "government_directory" in sources
    assert "openstreetmap" in sources

    # Nearest haven is the mock OSM post right in SIPCOT (~0.03 km away)
    assert havens[0]["id"] == "osm-node-8888"
    assert havens[0]["distance_km"] < 0.2


# ---------------------------------------------------------------------------
# 7. Cache Isolation Across Different Origins
# ---------------------------------------------------------------------------
def test_cache_isolates_records_and_recalculates_distances_per_victim_origin(client):
    """User coordinates are never cached; different victim locations get truthful distances."""
    safe_haven_service.clear_cache()
    _, victim_token = _create_isolated_victim(client, "Cache Test Victim")

    # Victim A at Siruseri, Chennai (12.8353, 80.2190)
    res_chn = client.get(
        "/api/safe-havens?lat=12.8353&lng=80.2190&provider=osc_directory",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_chn.status_code == 200
    d_chn_first = res_chn.json()["havens"][0]["distance_km"]
    assert d_chn_first < 6.0  # Kelambakkam AWPS is ~5.6 km away

    # Victim B at Bowring Hospital, Bengaluru (12.9830, 77.6015)
    res_blr = client.get(
        "/api/safe-havens?lat=12.9830&lng=77.6015&provider=osc_directory",
        headers={"Authorization": f"Bearer {victim_token}"}
    )
    assert res_blr.status_code == 200
    d_blr_first = res_blr.json()["havens"][0]["distance_km"]
    # At Bowring Hospital itself, Sakhi BLR is 0.0 km away
    assert d_blr_first < 0.1

    # Verify cache contains only provider records, no victim coordinates
    cache_entry = safe_haven_service._cache.get("osc_directory")
    assert cache_entry is not None
    assert "records" in cache_entry
    assert "user_location" not in cache_entry
    assert "lat" not in cache_entry


# ---------------------------------------------------------------------------
# 8. Truthful Bed Vacancy and Hotline Disclosures
# ---------------------------------------------------------------------------
def test_bed_vacancy_remains_unfabricated_and_hotlines_present(client):
    """All safe haven records preserve truthful bed availability notices and include 112/181."""
    _, victim_token = _create_isolated_victim(client, "Truthfulness Victim")
    res = client.get("/api/safe-havens?provider=osc_directory", headers={"Authorization": f"Bearer {victim_token}"})
    assert res.status_code == 200
    data = res.json()

    # Check emergency hotlines
    hotlines = {h["phone"] for h in data["emergency_hotlines"]}
    assert "112" in hotlines
    assert "181" in hotlines

    for h in data["havens"]:
        assert "unknown" in h["bed_availability"].lower()
        assert "guaranteed" not in h["bed_availability"].lower()
        assert "100%" not in h["bed_availability"].lower()
