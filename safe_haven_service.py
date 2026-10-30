"""
NIVARA Safe Haven Service & Provider Architecture — Task 9
Handles real-world verified shelter directories, live external providers (e.g. OpenStreetMap Overpass),
and demonstration fallbacks with strict source attribution, distance accuracy, and truthfulness.
"""

import os
import json
import time
import math
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("nivara_safe_haven")


def calculate_haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two points on Earth in kilometers.
    Returns float('inf') safely if coordinates are invalid, out-of-range, or missing.
    """
    try:
        if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
            return float("inf")
        lat1, lon1, lat2, lon2 = float(lat1), float(lon1), float(lat2), float(lon2)
        if any(math.isnan(v) or math.isinf(v) for v in (lat1, lon1, lat2, lon2)):
            return float("inf")
        if not (-90.0 <= lat1 <= 90.0 and -90.0 <= lat2 <= 90.0 and -180.0 <= lon1 <= 180.0 and -180.0 <= lon2 <= 180.0):
            return float("inf")
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
        a = min(1.0, max(0.0, a))
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c
    except Exception:
        return float("inf")


class SafeHavenRecord(BaseModel):
    id: str
    name: str
    type: str = "shelter"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    address: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    phone: Optional[str] = None
    helpline: Optional[str] = None
    operating_hours: Optional[str] = "unknown"
    services: List[str] = Field(default_factory=list)
    source_name: str
    source_type: str = "government_directory"  # government_directory | openstreetmap | verified_ngo | demonstration
    is_verified_source: bool = False
    is_location_verified: bool = False
    bed_availability: str = "unknown"
    last_updated: Optional[str] = None
    distance_km: Optional[float] = None
    distance_type: Optional[str] = None  # "straight_line" or None
    disclaimer: str

    # Legacy compatibility fields for older UI components
    status: Optional[str] = None
    capacity: Optional[str] = None
    security_level: Optional[str] = None
    is_verified: bool = False
    data_source: Optional[str] = None


class BaseSafeHavenProvider(ABC):
    @abstractmethod
    async def fetch_havens(self, lat: Optional[float] = None, lng: Optional[float] = None, radius_km: float = 50.0) -> List[SafeHavenRecord]:
        """Fetch raw havens from provider and normalize into SafeHavenRecord models."""
        pass

    @property
    @abstractmethod
    def provider_id(self) -> str:
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def is_verified(self) -> bool:
        pass

    @property
    @abstractmethod
    def provider_notice(self) -> str:
        pass


class GovernmentOSCDirectoryProvider(BaseSafeHavenProvider):
    """
    Verified public directory provider for official One Stop Centres (Sakhi Centres)
    established under Mission Shakti (Sambal) by the Ministry of Women and Child Development (MWCD),
    Government of India, and state emergency crisis hubs.
    """
    def __init__(self, data_file_path: Optional[str] = None):
        if data_file_path:
            self.data_file = data_file_path
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.data_file = os.path.join(base_dir, "data", "verified_safe_havens_india.json")

    @property
    def provider_id(self) -> str:
        return "osc_directory"

    @property
    def provider_name(self) -> str:
        return "Ministry of Women and Child Development (MWCD) — Mission Shakti One Stop Centre Directory"

    @property
    def is_verified(self) -> bool:
        return True

    @property
    def provider_notice(self) -> str:
        return (
            "Verified Government Directory: Center locations, phone numbers, and emergency lines (181/112) "
            "are sourced from official public directories. Immediate bed/room availability is NOT tracked online in real time. "
            "Always contact the facility or call 181 Women Helpline directly before traveling."
        )

    async def fetch_havens(self, lat: Optional[float] = None, lng: Optional[float] = None, radius_km: float = 50.0) -> List[SafeHavenRecord]:
        if not os.path.exists(self.data_file):
            logger.warning(f"Verified Safe Haven data file not found at {self.data_file}")
            return []

        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as e:
            logger.error(f"Error reading verified Safe Haven dataset: {e}")
            return []

        records = []
        for item in raw_data:
            rec = SafeHavenRecord(
                id=item["id"],
                name=item["name"],
                type=item.get("type", "one_stop_centre"),
                latitude=item.get("latitude"),
                longitude=item.get("longitude"),
                address=item.get("address"),
                district=item.get("district"),
                state=item.get("state"),
                phone=item.get("phone"),
                helpline=item.get("helpline"),
                operating_hours=item.get("operating_hours", "24x7 Emergency Intake"),
                services=item.get("services", []),
                source_name=item.get("source_name", self.provider_name),
                source_type="government_directory",
                is_verified_source=True,
                is_location_verified=True,
                bed_availability=item.get("bed_availability", "unknown - temporary shelter (up to 5 days); confirm intake via 181 helpline"),
                last_updated=item.get("last_updated", "2024-Q3 Directory Review"),
                disclaimer=item.get("disclaimer", "Official directory listing. Immediate availability not tracked online."),
                # Backward-compatibility fields
                status="Verified Directory Record",
                capacity=f"{len(item.get('services', []))} Integrated Crisis Services",
                security_level="Government Designated Safe Space",
                is_verified=True,
                data_source="government_directory"
            )
            records.append(rec)

        return records


class OpenStreetMapOverpassProvider(BaseSafeHavenProvider):
    """
    Live external provider querying OpenStreetMap Overpass API for community-mapped
    social facilities, women's support centers, police stations, hospitals, clinics, and legal aid.
    """
    DEFAULT_ENDPOINTS = [
        "https://overpass-api.de/api/interpreter",
        "https://overpass.kumi.systems/api/interpreter",
        "https://maps.mail.ru/osm/tools/overpass/api/interpreter"
    ]

    def __init__(self, endpoint_url: Optional[str] = None, timeout_seconds: float = 8.0):
        self.endpoint_url = endpoint_url or os.environ.get("OVERPASS_API_URL")
        if self.endpoint_url:
            self.endpoints = [self.endpoint_url]
        else:
            self.endpoints = self.DEFAULT_ENDPOINTS
        self.timeout = timeout_seconds

    @property
    def provider_id(self) -> str:
        return "openstreetmap"

    @property
    def provider_name(self) -> str:
        return "OpenStreetMap Community Contributors (Overpass API)"

    @property
    def is_verified(self) -> bool:
        return False  # OpenStreetMap is open-collaborative, not an official government directory

    @property
    def provider_notice(self) -> str:
        return (
            "OpenStreetMap Community Data: Shelter and emergency points are sourced from public collaborative maps. "
            "Operating hours, telephone contacts, and availability are unverified and may be incomplete. "
            "Verify via local emergency numbers (112 / 181) before traveling."
        )

    async def fetch_havens(self, lat: Optional[float] = None, lng: Optional[float] = None, radius_km: float = 50.0) -> List[SafeHavenRecord]:
        if lat is None or lng is None:
            # Overpass query requires coordinates
            return []

        radius_meters = int(min(radius_km * 1000, 30000))  # Cap query radius at 30km for Overpass performance

        query = f"""[out:json][timeout:{int(self.timeout)}];
(
  nwr["amenity"="police"](around:{radius_meters},{lat},{lng});
  nwr["amenity"="hospital"](around:{radius_meters},{lat},{lng});
  nwr["amenity"="clinic"](around:{radius_meters},{lat},{lng});
  nwr["healthcare"="hospital"](around:{radius_meters},{lat},{lng});
  nwr["amenity"="social_facility"](around:{radius_meters},{lat},{lng});
  nwr["social_facility"="shelter"](around:{radius_meters},{lat},{lng});
  nwr["office"="legal"](around:{radius_meters},{lat},{lng});
);
out center 35;
"""
        data = None
        for endpoint in self.endpoints:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    res = await client.post(endpoint, data={"data": query})
                    if res.status_code == 200:
                        data = res.json()
                        break
                    else:
                        logger.warning(f"Overpass endpoint {endpoint} returned status {res.status_code}")
            except Exception as e:
                logger.warning(f"Overpass endpoint {endpoint} failed or timed out: {e}")

        if not data:
            return []

        elements = data.get("elements", [])
        records = []
        seen_keys = set()

        for el in elements:
            tags = el.get("tags", {})
            osm_type = el.get("type", "node")
            osm_id = str(el.get("id"))

            node_lat = el.get("lat")
            node_lon = el.get("lon")
            if node_lat is None or node_lon is None:
                center = el.get("center")
                if isinstance(center, dict):
                    node_lat = center.get("lat")
                    node_lon = center.get("lon")

            if node_lat is None or node_lon is None:
                continue

            try:
                node_lat = float(node_lat)
                node_lon = float(node_lon)
            except (ValueError, TypeError):
                continue

            amenity = tags.get("amenity", "")
            healthcare = tags.get("healthcare", "")
            office = tags.get("office", "")
            social_facility = tags.get("social_facility", "")

            if amenity == "police":
                rec_type = "police"
            elif amenity in ["hospital", "clinic"] or healthcare == "hospital":
                rec_type = "hospital"
            elif office == "legal":
                rec_type = "legal_aid"
            elif amenity == "social_facility" or social_facility == "shelter":
                rec_type = "shelter"
            else:
                rec_type = "shelter"

            name = tags.get("name") or tags.get("name:en") or tags.get("operator") or f"Public Safety Facility ({osm_type.capitalize()} #{osm_id})"

            # Deduplication key based on coarse coordinates and name
            coord_key = f"{round(node_lat, 4)}_{round(node_lon, 4)}"
            name_key = name.strip().lower()
            if (coord_key, name_key) in seen_keys or osm_id in seen_keys:
                continue
            seen_keys.add((coord_key, name_key))
            seen_keys.add(osm_id)

            addr_parts = [tags.get("addr:housenumber"), tags.get("addr:street"), tags.get("addr:suburb"), tags.get("addr:city")]
            constructed_addr = ", ".join([p for p in addr_parts if p]) or tags.get("addr:full") or f"Coordinates ({round(node_lat, 4)}, {round(node_lon, 4)})"

            records.append(SafeHavenRecord(
                id=f"osm-{osm_type}-{osm_id}",
                name=name,
                type=rec_type,
                latitude=node_lat,
                longitude=node_lon,
                address=constructed_addr,
                district=tags.get("addr:district") or tags.get("addr:city"),
                state=tags.get("addr:state"),
                phone=tags.get("phone") or tags.get("contact:phone") or "112 (Emergency) / 1091 (Police Helpline)",
                helpline="112 (Emergency) / 181 (Women Helpline)",
                operating_hours=tags.get("opening_hours") or "24/7 (Emergency Service) / Verify by Phone",
                services=[f"Community Mapped {rec_type.replace('_', ' ').capitalize()}"],
                source_name=self.provider_name,
                source_type="openstreetmap",
                is_verified_source=False,
                is_location_verified=False,
                bed_availability="unknown - OpenStreetMap community mapping does not track live vacancy",
                last_updated="OpenStreetMap Live Overpass Query",
                disclaimer="Crowdsourced geographic data. Operating hours and facility availability are unverified; contact directly before traveling.",
                # Backward-compatibility
                status="Community Open Data",
                capacity="Public Facility",
                security_level="Community Mapping Record",
                is_verified=False,
                data_source="openstreetmap"
            ))

        return records



class DemoSafeHavenProvider(BaseSafeHavenProvider):
    """
    Curated demonstration provider for development, testing, and training environments.
    Strictly identifies every record as demonstration data.
    """
    DEMO_RECORDS = [
        {
            "id": "demo-sh-1",
            "name": "Central Women's Safety Shelter & Crisis Care (Demo)",
            "type": "shelter",
            "latitude": 12.9798,
            "longitude": 77.6011,
            "status": "Demonstration Record",
            "phone": "+91 80 2294 2222 (Sample)",
            "capacity": "Demo Shelter (Sample capacity)",
            "security_level": "Designated Sample Safe Haven",
            "address": "Ashok Nagar / Richmond Corridor, Bengaluru",
            "services": ["Sample Emergency Shelter", "Counseling Demo"],
            "operating_hours": "Demo Hours",
            "bed_availability": "unknown (Demonstration)",
            "is_verified": False,
            "data_source": "demo_reference"
        },
        {
            "id": "demo-sh-2",
            "name": "Metro Division Police Help Desk (Demo)",
            "type": "police",
            "latitude": 12.9662,
            "longitude": 77.6024,
            "status": "Demonstration Record",
            "phone": "112 / 1091 (National Emergency)",
            "capacity": "Sample Police Station Hub",
            "security_level": "Police Assistance Booth",
            "address": "Brigade Road Intersection, Bengaluru",
            "services": ["Police Assistance Demo"],
            "operating_hours": "Demo Hours",
            "bed_availability": "unknown (Non-residential)",
            "is_verified": False,
            "data_source": "demo_reference"
        },
        {
            "id": "demo-sh-3",
            "name": "Community Crisis Medical Aid Hub (Demo)",
            "type": "hospital",
            "latitude": 12.9841,
            "longitude": 77.5904,
            "status": "Demonstration Record",
            "phone": "108 / 112 (Ambulance Helpline)",
            "capacity": "Sample Medical Support",
            "security_level": "Hospital Emergency Wing",
            "address": "Residency Road Medical Area, Bengaluru",
            "services": ["Medical Care Demo"],
            "operating_hours": "Demo Hours",
            "bed_availability": "unknown (Demonstration)",
            "is_verified": False,
            "data_source": "demo_reference"
        },
        {
            "id": "demo-sh-4",
            "name": "Legal Aid & Safe Haven Community Hub (Demo)",
            "type": "legal_aid",
            "latitude": 12.9625,
            "longitude": 77.5861,
            "status": "Demonstration Record",
            "phone": "15100 (Tele-Law National Helpline)",
            "capacity": "Sample Counseling Space",
            "security_level": "Civic Center Safe Space",
            "address": "Richmond Town Civic Area, Bengaluru",
            "services": ["Legal Aid Demo"],
            "operating_hours": "Demo Hours",
            "bed_availability": "unknown (Non-residential)",
            "is_verified": False,
            "data_source": "demo_reference"
        }
    ]

    @property
    def provider_id(self) -> str:
        return "demo"

    @property
    def provider_name(self) -> str:
        return "NIVARA Demonstration Sample Reference"

    @property
    def is_verified(self) -> bool:
        return False

    @property
    def provider_notice(self) -> str:
        return (
            "Demonstration data only. Verified external safe-haven registries (e.g. government shelter directories or OpenStreetMap Overpass) "
            "are not connected in this environment. Do not rely on these locations during an actual emergency. "
            "Always dial 112 or local emergency services directly."
        )

    async def fetch_havens(self, lat: Optional[float] = None, lng: Optional[float] = None, radius_km: float = 50.0) -> List[SafeHavenRecord]:
        records = []
        for d in self.DEMO_RECORDS:
            records.append(SafeHavenRecord(
                id=d["id"],
                name=d["name"],
                type=d.get("type", "shelter"),
                latitude=d.get("latitude"),
                longitude=d.get("longitude"),
                address=d.get("address"),
                phone=d.get("phone"),
                helpline="112 / 1091 (Emergency)",
                operating_hours=d.get("operating_hours", "Demo Hours"),
                services=d.get("services", ["Sample Support"]),
                source_name=self.provider_name,
                source_type="demonstration",
                is_verified_source=False,
                is_location_verified=False,
                bed_availability=d.get("bed_availability", "unknown (Demonstration Sample)"),
                last_updated="Demo Baseline",
                disclaimer="Simulated sample location for interface testing. Not an actual shelter.",
                status=d.get("status", "Demonstration Record"),
                capacity=d.get("capacity"),
                security_level=d.get("security_level"),
                is_verified=False,
                data_source="demo_reference"
            ))
        return records


class SafeHavenService:
    """
    Orchestrates Safe Haven queries, provider selection, in-memory TTL caching,
    accurate Haversine straight-line distance calculations, and metadata reporting.
    """
    def __init__(self):
        self._providers: Dict[str, BaseSafeHavenProvider] = {
            "osc_directory": GovernmentOSCDirectoryProvider(),
            "openstreetmap": OpenStreetMapOverpassProvider(),
            "demo": DemoSafeHavenProvider()
        }
        # In-memory cache for provider records:
        # Structure: { cache_key: {"timestamp": float, "records": List[SafeHavenRecord]} }
        # NOTE: Never caches user coordinates. Caches only raw provider records.
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = float(os.environ.get("SAFE_HAVEN_CACHE_TTL_SECONDS", "900"))

    def get_provider(self, provider_id: Optional[str] = None) -> BaseSafeHavenProvider:
        requested = (provider_id or os.environ.get("SAFE_HAVEN_PROVIDER", "osc_directory")).strip().lower()
        if requested in ["osc", "osc_directory", "government", "verified"]:
            return self._providers["osc_directory"]
        elif requested in ["osm", "openstreetmap", "overpass"]:
            return self._providers["openstreetmap"]
        elif requested in ["demo", "demo_reference", "sample"]:
            return self._providers["demo"]
        return self._providers.get(requested, self._providers["osc_directory"])

    def clear_cache(self):
        """Clears in-memory provider cache (useful for testing)."""
        self._cache.clear()

    async def get_safe_havens(
        self,
        lat: Optional[float] = None,
        lng: Optional[float] = None,
        provider_name: Optional[str] = None,
        radius_km: float = 50.0
    ) -> Dict[str, Any]:
        has_coords = False
        if lat is not None and lng is not None:
            if -90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0:
                has_coords = True

        try:
            effective_radius = float(radius_km) if radius_km is not None and float(radius_km) > 0 else 50.0
        except (ValueError, TypeError):
            effective_radius = 50.0

        req_provider = (provider_name or os.environ.get("SAFE_HAVEN_PROVIDER", "osc_directory")).strip().lower()
        is_aggregate = req_provider in ["all", "aggregate", "combined"]

        now = time.time()
        raw_records = []

        if is_aggregate:
            # Aggregate osc_directory and openstreetmap
            osc_provider = self._providers["osc_directory"]
            osm_provider = self._providers["openstreetmap"]

            # Cache fetch for osc_directory
            cached_osc = self._cache.get("osc_directory")
            if cached_osc and (now - cached_osc["timestamp"]) < self._cache_ttl:
                osc_recs = cached_osc["records"]
            else:
                osc_recs = await osc_provider.fetch_havens(lat=lat, lng=lng, radius_km=effective_radius)
                self._cache["osc_directory"] = {"timestamp": now, "records": osc_recs}

            # Cache fetch for openstreetmap
            osm_cache_key = f"osm_{round(lat, 1)}_{round(lng, 1)}" if has_coords else "osm_global"
            cached_osm = self._cache.get(osm_cache_key)
            if cached_osm and (now - cached_osm["timestamp"]) < self._cache_ttl:
                osm_recs = cached_osm["records"]
            else:
                osm_recs = await osm_provider.fetch_havens(lat=lat, lng=lng, radius_km=effective_radius)
                self._cache[osm_cache_key] = {"timestamp": now, "records": osm_recs}

            raw_records = list(osc_recs) + list(osm_recs)
            provider_id_val = "all"
            provider_name_val = "Combined Directory (Government MWCD + OpenStreetMap Community)"
            provider_notice_val = (
                "Combined view showing official Government One Stop Centres along with OpenStreetMap community-mapped "
                "emergency hubs. In any immediate crisis, call 112 or 181 directly."
            )
            is_verified_val = False
        else:
            provider = self.get_provider(provider_name)
            provider_id_val = provider.provider_id
            provider_name_val = provider.provider_name
            provider_notice_val = provider.provider_notice
            is_verified_val = provider.is_verified

            cache_key = provider.provider_id
            if provider.provider_id == "openstreetmap" and has_coords:
                cache_key = f"osm_{round(lat, 1)}_{round(lng, 1)}"

            cached = self._cache.get(cache_key)
            if cached and (now - cached["timestamp"]) < self._cache_ttl:
                raw_records = cached["records"]
            else:
                raw_records = await provider.fetch_havens(lat=lat, lng=lng, radius_km=effective_radius)
                self._cache[cache_key] = {"timestamp": now, "records": raw_records}

        # Compute accurate Haversine distances dynamically for this specific request
        results = []
        for r in raw_records:
            item = r.model_copy()
            if has_coords and item.latitude is not None and item.longitude is not None:
                d = calculate_haversine(lat, lng, item.latitude, item.longitude)
                if d != float("inf"):
                    item.distance_km = round(d, 2)
                    item.distance_type = "straight_line"
                else:
                    item.distance_km = None
                    item.distance_type = None
            else:
                item.distance_km = None
                item.distance_type = None
            results.append(item.model_dump())

        # Sort by distance if available, placing records with distance first (nearest first)
        if has_coords:
            results.sort(key=lambda x: (x["distance_km"] is None, x["distance_km"] or 0))

        # Coverage analysis based on effective_radius
        within_radius = [h for h in results if h.get("distance_km") is not None and h["distance_km"] <= effective_radius]
        within_radius_count = len(within_radius)
        nearest_distance_km = results[0]["distance_km"] if (results and results[0].get("distance_km") is not None) else None

        if has_coords:
            if within_radius_count == 0:
                is_local_coverage_limited = True
                nearest_desc = f"{nearest_distance_km} km away ({results[0]['name']})" if nearest_distance_km is not None else "unavailable"
                coverage_notice = (
                    f"No verified safe haven facility found within {int(effective_radius)} km of your location. "
                    f"The nearest centre is {nearest_desc}. You can expand the search radius, check OpenStreetMap "
                    f"for local community facilities, or dial 181 Women Helpline or 112 directly."
                )
            else:
                is_local_coverage_limited = False
                coverage_notice = f"Found {within_radius_count} verified safe haven facility/ies within {int(effective_radius)} km of your location."
        else:
            is_local_coverage_limited = False
            coverage_notice = "Showing all directory centres across India. Enable GPS location to view straight-line distance and sort by proximity."

        return {
            "verified_provider_configured": is_verified_val,
            "provider_id": provider_id_val,
            "provider_name": provider_name_val,
            "provider_notice": provider_notice_val,
            "source_type": provider_id_val,
            "user_location": {"latitude": lat, "longitude": lng} if has_coords else None,
            "has_user_location": has_coords,
            "distance_calculation_method": "Haversine straight-line distance (km)" if has_coords else None,
            "radius_km": effective_radius,
            "within_radius_count": within_radius_count,
            "nearest_distance_km": nearest_distance_km,
            "is_local_coverage_limited": is_local_coverage_limited,
            "coverage_notice": coverage_notice,
            "emergency_hotlines": [
                {"service": "National Emergency Number", "phone": "112", "number": "112"},
                {"service": "Women Helpline (All India)", "phone": "181", "number": "181"},
                {"service": "Women Police Helpline", "phone": "1091", "number": "1091"},
                {"service": "National Commission for Women", "phone": "7827170170", "number": "7827170170"},
                {"service": "Tele-MANAS Mental Health Helpline", "phone": "14416", "number": "14416"}
            ],
            "center": {"latitude": lat if has_coords else 12.9716, "longitude": lng if has_coords else 77.5946},
            "havens": results
        }


# Global singleton instance
safe_haven_service = SafeHavenService()
