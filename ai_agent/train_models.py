import pandas as pd
import os
import pickle
import torch
import io
import sys
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification, 
    TrainingArguments, 
    Trainer,
    DataCollatorWithPadding
)
from datasets import Dataset

# Fix encoding issue for Windows environment when printing emojis
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Setup paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

def train_url_model():
    print("\n--- Retraining URL ML Model ---")
    df = pd.read_csv(os.path.join(DATA_DIR, 'malicious_url_dataset.csv'))
    
    # Map labels to binary
    df['label'] = df['label'].map({'malicious': 1, 'benign': 0})
    
    X = df['url']
    y = df['label']
    
    # Evaluate accuracy using train-test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    eval_vectorizer = TfidfVectorizer(max_features=5000)
    X_train_vec = eval_vectorizer.fit_transform(X_train)
    X_test_vec = eval_vectorizer.transform(X_test)
    
    eval_model = LogisticRegression(max_iter=1000)
    eval_model.fit(X_train_vec, y_train)
    
    y_pred = eval_model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"URL Model Validation Accuracy (80/20 split): {acc:.4%}")
    
    # Train on full dataset for maximum performance in production
    vectorizer = TfidfVectorizer(max_features=5000)
    X_vec = vectorizer.fit_transform(X)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_vec, y)
    
    # Save models
    with open(os.path.join(MODEL_DIR, 'phishing_new.pkl'), 'wb') as f:
        pickle.dump(model, f)
    with open(os.path.join(MODEL_DIR, 'vectorizerurl_new.pkl'), 'wb') as f:
        pickle.dump(vectorizer, f)
    
    print("URL model updated and saved as phishing_new.pkl")

def finetuned_deberta():
    print("\n--- Fine-tuning DeBERTa for Text Analysis ---")
    
    # 1. Load Data
    # Phishing Emails
    df_phish = pd.read_csv(os.path.join(DATA_DIR, 'phishing_email_dataset.csv'))
    df_phish = df_phish[['text', 'label']].rename(columns={'label': 'target'})
    # FIX: Correctly map phishing and legitimate labels
    df_phish['target'] = df_phish['target'].map({'phishing': 1, 'legitimate': 0})
    
    # Spam Dataset
    df_spam = pd.read_csv(os.path.join(DATA_DIR, 'spam_detection_dataset.csv'))
    df_spam['target'] = df_spam['label'].map({'spam': 1, 'ham': 0})
    df_spam = df_spam[['text', 'target']]
    
    # Combine
    combined_df = pd.concat([df_phish, df_spam]).dropna().sample(frac=1, random_state=42).reset_index(drop=True)
    
    # 2. Tokenization
    model_name = "microsoft/deberta-v3-small"
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=False)
    
    def tokenize_function(examples):
        return tokenizer(examples['text'], truncation=True, padding='max_length', max_length=256)
    
    # Limit dataset size for quick fine-tuning (agent environment)
    # 2000 samples is enough to adapt
    train_subset = combined_df.head(2000)
    dataset = Dataset.from_pandas(train_subset)
    dataset = dataset.rename_column("target", "label")
    tokenized_ds = dataset.map(tokenize_function, batched=True)
    
    # 3. Model Setup
    device = "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2).to(device)
    
    # Freeze the backbone DeBERTa layers to speed up CPU training significantly
    print("Freezing DeBERTa backbone for faster training/fine-tuning...")
    for name, param in model.named_parameters():
        if "classifier" not in name:
            param.requires_grad = False
            
    # Print trainable parameters summary
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Trainable parameters: {trainable_params:,} / {total_params:,}")
    
    # 4. Training
    training_args = TrainingArguments(
        output_dir="./temp_results",
        num_train_epochs=1,
        per_device_train_batch_size=8,
        weight_decay=0.01,
        logging_dir="./logs",
        use_mps_device=torch.backends.mps.is_available(),
        save_strategy="no", # Save manually to models dir
        eval_strategy="no",
        report_to="none"
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_ds,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
    )
    
    trainer.train()
    
    # 5. Save
    save_path = os.path.join(MODEL_DIR, 'fine_tuned_deberta')
    trainer.save_model(save_path)
    tokenizer.save_pretrained(save_path)
    print(f"Fine-tuned DeBERTa saved to {save_path}")

def train_text_scikit():
    print("\n--- Retraining Scikit-Learn Text Model ---")
    # Phishing Emails
    df_phish = pd.read_csv(os.path.join(DATA_DIR, 'phishing_email_dataset.csv'))
    df_phish = df_phish[['text', 'label']].rename(columns={'label': 'target'})
    # FIX: Correctly map phishing and legitimate labels instead of setting all to 1
    df_phish['target'] = df_phish['target'].map({'phishing': 1, 'legitimate': 0})
    
    # Spam Dataset
    df_spam = pd.read_csv(os.path.join(DATA_DIR, 'spam_detection_dataset.csv'))
    df_spam['target'] = df_spam['label'].map({'spam': 1, 'ham': 0})
    df_spam = df_spam[['text', 'target']]
    
    combined_df = pd.concat([df_phish, df_spam]).dropna()
    
    X = combined_df['text']
    y = combined_df['target']
    
    # Evaluate accuracy using train-test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    eval_vectorizer = TfidfVectorizer(max_features=5000)
    X_train_vec = eval_vectorizer.fit_transform(X_train)
    X_test_vec = eval_vectorizer.transform(X_test)
    
    eval_model = LogisticRegression(max_iter=1000)
    eval_model.fit(X_train_vec, y_train)
    
    y_pred = eval_model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    print(f"Text Scikit Model Validation Accuracy (80/20 split): {acc:.4%}")
    
    # Train on full dataset for maximum performance in production
    vectorizer = TfidfVectorizer(max_features=5000)
    X_vec = vectorizer.fit_transform(X)
    
    model = LogisticRegression(max_iter=1000)
    model.fit(X_vec, y)
    
    with open(os.path.join(MODEL_DIR, 'model_new.pkl'), 'wb') as f:
        pickle.dump(model, f)
    with open(os.path.join(MODEL_DIR, 'vectorizer_new.pkl'), 'wb') as f:
        pickle.dump(vectorizer, f)
    
    print("Scikit text model updated and saved as model_new.pkl")

if __name__ == "__main__":
    train_url_model()
    train_text_scikit()
    # finetuned_deberta() # Disabled by default due to high CPU execution time in standard runs
    print("\n✅ Multi-Agent system updated with new knowledge from local datasets.")
