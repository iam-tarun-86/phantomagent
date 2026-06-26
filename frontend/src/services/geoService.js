// Cache for IP geolocation to avoid repeated API calls
const geoCache = new Map();

// Free IP geolocation API (no key required, rate limited)
const GEO_API_URL = 'http://ip-api.com/json';

export const getIPLocation = async (ip) => {
    // Return cached result if available
    if (geoCache.has(ip)) {
        return geoCache.get(ip);
    }

    // Don't geocode private/local IPs
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === 'localhost' || ip === '127.0.0.1') {
        const fallback = { lat: 20 + Math.random() * 20, lon: 70 + Math.random() * 40, country: 'Local Network', city: 'Internal' };
        geoCache.set(ip, fallback);
        return fallback;
    }

    try {
        const response = await fetch(`${GEO_API_URL}/${ip}?fields=lat,lon,country,city,status,message`);
        const data = await response.json();

        if (data.status === 'success') {
            const location = {
                lat: data.lat,
                lon: data.lon,
                country: data.country,
                city: data.city
            };
            geoCache.set(ip, location);
            return location;
        } else {
            throw new Error(data.message || 'Geolocation failed');
        }
    } catch (error) {
        console.log(`[GEO] Failed to locate ${ip}:`, error.message);
        // Return random fallback location
        const fallback = {
            lat: (Math.random() - 0.5) * 160,
            lon: (Math.random() - 0.5) * 360,
            country: 'Unknown',
            city: 'Unknown'
        };
        geoCache.set(ip, fallback);
        return fallback;
    }
};

// Convert lat/lon to 2D map coordinates (simple equirectangular projection)
export const latLonToXY = (lat, lon, width, height) => {
    const x = ((lon + 180) / 360) * width;
    const y = ((90 - lat) / 180) * height;
    return { x, y };
};