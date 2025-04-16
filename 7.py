import geocoder

g = geocoder.ip('me')
print(g.latlng)  # Např. [50.0870, 14.4208]
