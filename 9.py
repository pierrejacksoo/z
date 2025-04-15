from geopy.geocoders import Nominatim

# Inicializace geolokátora
geolocator = Nominatim(user_agent="geoapiExercises")

# Získání informací o lokaci na základě názvu místa
location = geolocator.geocode("Prague, Czech Republic")

print(f"Address: {location.address}")
print(f"Latitude: {location.latitude}, Longitude: {location.longitude}")
