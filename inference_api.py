from flask import Flask, jsonify, request
from flask_cors import CORS
import numpy as np
import tensorflow as tf
import keras
import datetime

app = Flask(__name__)
CORS(app)


# Correct model architecture for 6 features
def create_model():
    model = keras.models.Sequential([
        keras.layers.InputLayer(input_shape=(6, 1)),  # Changed to 6 features
        keras.layers.LSTM(32, activation='tanh'),
        keras.layers.Dropout(0.5),
        keras.layers.Dense(10, activation='relu'),
        keras.layers.Dense(1, activation='sigmoid')  # Binary classification
    ])
    return model


# Initialize model
try:
    model = create_model()
    # Dummy weights for demonstration
    model.predict(np.zeros((1, 6, 1)))  # Initialize weights
    print("Model initialized!")
except Exception as e:
    print(f"Model error: {e}")
    raise

predictions_db = []


@app.route('/predict', methods=['POST'])
def predict():
    try:
        features = np.array(request.json['features'])
        features = features.reshape(-1, 6, 1)  # Match 6 features

        # Mock prediction (replace with real model)
        predictions = np.random.rand(features.shape[0], 1)  # Random scores
        is_attack = (predictions > 0.7).astype(int).tolist()

        # Store predictions
        new_preds = [{
            "timestamp": datetime.datetime.now().isoformat(),
            "is_attack": bool(pred[0])
        } for pred in is_attack]

        predictions_db.extend(new_preds)
        return jsonify({"status": "success", "predictions": is_attack})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/predictions', methods=['GET'])
def get_predictions():
    return jsonify(predictions_db[-10:])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)