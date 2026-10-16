import pandas as pd
import os
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

def evaluate_models():
    print("=" * 70)
    print("      AEGISAI REAL UN-LEAKED MODEL EVALUATION (80/20 STRATIFIED)")
    print("=" * 70)
    
    # --- 1. URL Model Evaluation ---
    print("\n[1] Evaluating Character N-Gram URL Classifier...")
    url_df = pd.read_csv(os.path.join(DATA_DIR, 'malicious_url_dataset.csv'))
    url_df['label'] = url_df['label'].map({'malicious': 1, 'benign': 0})
    X_url = url_df['url']
    y_url = url_df['label']

    X_train_url, X_test_url, y_train_url, y_test_url = train_test_split(
        X_url, y_url, test_size=0.20, random_state=42, stratify=y_url
    )

    url_vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=10000)
    X_train_url_vec = url_vec.fit_transform(X_train_url)
    X_test_url_vec = url_vec.transform(X_test_url)

    url_model = LogisticRegression(max_iter=1000, C=2.0, random_state=42)
    url_model.fit(X_train_url_vec, y_train_url)

    y_pred_url = url_model.predict(X_test_url_vec)
    cm_url = confusion_matrix(y_test_url, y_pred_url)

    print(f"  Test Set Size: {len(y_test_url)} samples")
    print(f"  Confusion Matrix:\n    TN: {cm_url[0,0]:<5} FP: {cm_url[0,1]:<5}\n    FN: {cm_url[1,0]:<5} TP: {cm_url[1,1]:<5}")
    print(f"  Accuracy:  {accuracy_score(y_test_url, y_pred_url):.4%}")
    print(f"  Precision: {precision_score(y_test_url, y_pred_url):.4%}")
    print(f"  Recall:    {recall_score(y_test_url, y_pred_url):.4%}")
    print(f"  F1-Score:  {f1_score(y_test_url, y_pred_url):.4%}")

    # --- 2. Text Model Evaluation ---
    print("\n[2] Evaluating Text (Phishing + Spam) Classifier...")
    df_phish = pd.read_csv(os.path.join(DATA_DIR, 'phishing_email_dataset.csv'))[['text', 'label']].rename(columns={'label': 'target'})
    df_phish['target'] = df_phish['target'].map({'phishing': 1, 'legitimate': 0})

    df_spam = pd.read_csv(os.path.join(DATA_DIR, 'spam_detection_dataset.csv'))
    df_spam['target'] = df_spam['label'].map({'spam': 1, 'ham': 0})
    df_spam = df_spam[['text', 'target']]

    text_df = pd.concat([df_phish, df_spam]).dropna().reset_index(drop=True)
    X_text = text_df['text']
    y_text = text_df['target']

    X_train_text, X_test_text, y_train_text, y_test_text = train_test_split(
        X_text, y_text, test_size=0.20, random_state=42, stratify=y_text
    )

    text_vec = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
    X_train_text_vec = text_vec.fit_transform(X_train_text)
    X_test_text_vec = text_vec.transform(X_test_text)

    text_model = LogisticRegression(max_iter=1000, C=2.0, random_state=42)
    text_model.fit(X_train_text_vec, y_train_text)

    y_pred_text = text_model.predict(X_test_text_vec)
    cm_text = confusion_matrix(y_test_text, y_pred_text)

    print(f"  Test Set Size: {len(y_test_text)} samples")
    print(f"  Confusion Matrix:\n    TN: {cm_text[0,0]:<5} FP: {cm_text[0,1]:<5}\n    FN: {cm_text[1,0]:<5} TP: {cm_text[1,1]:<5}")
    print(f"  Accuracy:  {accuracy_score(y_test_text, y_pred_text):.4%}")
    print(f"  Precision: {precision_score(y_test_text, y_pred_text):.4%}")
    print(f"  Recall:    {recall_score(y_test_text, y_pred_text):.4%}")
    print(f"  F1-Score:  {f1_score(y_test_text, y_pred_text):.4%}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    evaluate_models()
