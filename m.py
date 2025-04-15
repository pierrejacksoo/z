from geopy.geocoders import Nominatim

# Nastavení jedinečného user_agent
geolocator = Nominatim(user_agent="myGeocoderApp")

# Získání informací o lokaci na základě názvu místa
location = geolocator.geocode("Prague, Czech Republic")

if location:
    print(f"Address: {location.address}")
    print(f"Latitude: {location.latitude}, Longitude: {location.longitude}")
else:
    print("Location not found")
