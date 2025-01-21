import oqs
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/key-exchange", methods=["POST"])
def key_exchange():
    try:
        client_public_key = request.json.get("client_public_key")
        if not client_public_key:
            return jsonify({"error": "client_public_key is required"}), 400

        with oqs.KeyEncapsulation("Kyber1024") as kem:
            public_key = kem.generate_keypair()
            try:
                client_public_key_bytes = bytes.fromhex(client_public_key)
                ciphertext, shared_secret = kem.encap_secret(client_public_key_bytes)
            except Exception as e:
                return jsonify({"error": f"Error during encapsulation: {str(e)}"}), 400

            return jsonify({
                "ciphertext": ciphertext.hex(),
                "shared_secret": shared_secret.hex(),
                "public_key": public_key.hex()
            })
    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
