import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from feature_extraction import extract_features

# Load dataset
data = pd.read_csv("dataset/processed_phishing_dataset.csv")

# Extract features
feature_list = []

for url in data['url']:
    feature_list.append(extract_features(url))

X = pd.DataFrame(feature_list)
y = data['target']

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Model
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("Classification Report:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "model/phishing_model.pkl")

print("Model Saved Successfully!")
