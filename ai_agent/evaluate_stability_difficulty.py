"""
Tasks 5 & 6: Classical Model Stability Check & Dataset Difficulty Quantification
"""
import os
import sys
import re
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

SEEDS = [42, 100, 2024, 777, 999]

def evaluate_stability_and_difficulty():
    print("=" * 75)
    print("      TASK 5: CLASSICAL MODEL STABILITY CHECK ACROSS 5 RANDOM SEEDS")
    print("=" * 75)
    
    # --- 1. Load Datasets ---
    url_df = pd.read_csv(os.path.join(DATA_DIR, 'malicious_url_dataset.csv'))
    url_df['label'] = url_df['label'].map({'malicious': 1, 'benign': 0})
    X_url = url_df['url']
    y_url = url_df['label']

    df_phish = pd.read_csv(os.path.join(DATA_DIR, 'phishing_email_dataset.csv'))[['text', 'label']].rename(columns={'label': 'target'})
    df_phish['target'] = df_phish['target'].map({'phishing': 1, 'legitimate': 0})
    df_spam = pd.read_csv(os.path.join(DATA_DIR, 'spam_detection_dataset.csv'))
    df_spam['target'] = df_spam['label'].map({'spam': 1, 'ham': 0})
    df_spam = df_spam[['text', 'target']]
    text_df = pd.concat([df_phish, df_spam]).dropna().reset_index(drop=True)
    X_text = text_df['text']
    y_text = text_df['target']

    print("\n--- URL Classifier Stability (Char N-Gram Logistic Regression) ---")
    print(f"{'SEED':<8} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'CONFUSION MATRIX (TN FP FN TP)'}")
    print("-" * 75)
    
    url_seed_results = []
    for seed in SEEDS:
        X_tr, X_te, y_tr, y_te = train_test_split(X_url, y_url, test_size=0.20, random_state=seed, stratify=y_url)
        vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=10000)
        X_tr_v = vec.fit_transform(X_tr)
        X_te_v = vec.transform(X_te)
        model = LogisticRegression(max_iter=1000, C=2.0, random_state=seed)
        model.fit(X_tr_v, y_tr)
        y_pred = model.predict(X_te_v)
        
        acc = accuracy_score(y_te, y_pred)
        prec = precision_score(y_te, y_pred, zero_division=0)
        rec = recall_score(y_te, y_pred, zero_division=0)
        f1 = f1_score(y_te, y_pred, zero_division=0)
        cm = confusion_matrix(y_te, y_pred)
        url_seed_results.append((acc, prec, rec, f1))
        
        cm_str = f"[{cm[0,0]:<3} {cm[0,1]:<3} {cm[1,0]:<3} {cm[1,1]:<3}]"
        print(f"{seed:<8} | {acc:<10.4%} | {prec:<10.4%} | {rec:<10.4%} | {f1:<10.4%} | {cm_str}")

    print("\n--- Text Classifier Stability (Word N-Gram Logistic Regression) ---")
    print(f"{'SEED':<8} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'CONFUSION MATRIX (TN FP FN TP)'}")
    print("-" * 75)
    
    text_seed_results = []
    for seed in SEEDS:
        X_tr, X_te, y_tr, y_te = train_test_split(X_text, y_text, test_size=0.20, random_state=seed, stratify=y_text)
        vec = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
        X_tr_v = vec.fit_transform(X_tr)
        X_te_v = vec.transform(X_te)
        model = LogisticRegression(max_iter=1000, C=2.0, random_state=seed)
        model.fit(X_tr_v, y_tr)
        y_pred = model.predict(X_te_v)
        
        acc = accuracy_score(y_te, y_pred)
        prec = precision_score(y_te, y_pred, zero_division=0)
        rec = recall_score(y_te, y_pred, zero_division=0)
        f1 = f1_score(y_te, y_pred, zero_division=0)
        cm = confusion_matrix(y_te, y_pred)
        text_seed_results.append((acc, prec, rec, f1))
        
        cm_str = f"[{cm[0,0]:<3} {cm[0,1]:<3} {cm[1,0]:<3} {cm[1,1]:<3}]"
        print(f"{seed:<8} | {acc:<10.4%} | {prec:<10.4%} | {rec:<10.4%} | {f1:<10.4%} | {cm_str}")


    print("\n" + "=" * 75)
    print("      TASK 6: QUANTIFY DATASET DIFFICULTY (RULE BASELINE VS ML)")
    print("=" * 75)
    
    # Evaluate heuristic baseline on URL test set (seed 42)
    X_tr_url, X_te_url, y_tr_url, y_te_url = train_test_split(X_url, y_url, test_size=0.20, random_state=42, stratify=y_url)
    
    suspicious_keywords = ['verify', 'login', 'account', 'update', 'banking', 'secure', 'signin', 'claim', 'paypa', 'g00gle', 'amaz0n']
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.win', '.bid']
    
    y_pred_rule = []
    for url in X_te_url:
        u_lower = url.lower()
        is_suspicious = (
            '..' in u_lower or
            '@' in u_lower or
            re.search(r'https?://\d+\.\d+\.\d+\.\d+', u_lower) is not None or
            any(tld in u_lower for tld in suspicious_tlds) or
            any(kw in u_lower for kw in suspicious_keywords)
        )
        y_pred_rule.append(1 if is_suspicious else 0)

    cm_rule = confusion_matrix(y_te_url, y_pred_rule)
    acc_rule = accuracy_score(y_te_url, y_pred_rule)
    prec_rule = precision_score(y_te_url, y_pred_rule, zero_division=0)
    rec_rule = recall_score(y_te_url, y_pred_rule, zero_division=0)
    f1_rule = f1_score(y_te_url, y_pred_rule, zero_division=0)

    print("\n--- URL Dataset: Single-Rule Heuristic Baseline ---")
    print("  Rule logic: flag if URL contains IP address, double dots, suspicious TLDs (.xyz, .top, etc.), or keywords (login, verify, paypa, g00gle, etc.)")
    print(f"  Test Set Size: {len(y_te_url)}")
    print(f"  Confusion Matrix:\n    TN: {cm_rule[0,0]:<5} FP: {cm_rule[0,1]:<5}\n    FN: {cm_rule[1,0]:<5} TP: {cm_rule[1,1]:<5}")
    print(f"  Accuracy:  {acc_rule:.4%}")
    print(f"  Precision: {prec_rule:.4%}")
    print(f"  Recall:    {rec_rule:.4%}")
    print(f"  F1-Score:  {f1_rule:.4%}")
    
    print("\n--- Comparison: Heuristic Rule vs Classical ML Model ---")
    print(f"  Rule Baseline Accuracy : {acc_rule:.4%} (F1: {f1_rule:.4%})")
    print(f"  ML Model Accuracy      : {url_seed_results[0][0]:.4%} (F1: {url_seed_results[0][3]:.4%})")
    if acc_rule == url_seed_results[0][0]:
        print("  Verdict: The synthetic URL dataset is so surface-level separable that a simple 1-line heuristic rule achieves identical 100% accuracy to the ML model!")
    else:
        diff = url_seed_results[0][0] - acc_rule
        print(f"  Verdict: ML model adds +{diff:.2%} accuracy improvement over the heuristic rule baseline.")

    print("=" * 75)

if __name__ == "__main__":
    evaluate_stability_and_difficulty()
