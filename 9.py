from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return "Hello from adapter 1!"

if __name__ == "__main__":
    app.run(host="10.0.1.12", port=5000)
