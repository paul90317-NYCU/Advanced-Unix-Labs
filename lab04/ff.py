from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    visitor_ip = request.remote_addr
    response_data = {'ip': visitor_ip}
    return jsonify(response_data)

if __name__ == '__main__':
    app.run(debug=True,port=80)
