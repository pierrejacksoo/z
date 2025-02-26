import hashlib

# Define the weak password
weak_password = "987654321"  # Example of a weak password

# Generate the SHA-256 hash of the password
password_hash = hashlib.sha256(weak_password.encode()).hexdigest()

# Output the hash
print(password_hash)
