import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils import resample
from pathlib import Path

def smart_read_csv(path, **kwargs):
    """Try reading a CSV file with multiple encodings for robustness."""
    encodings = ["utf-8", "ISO-8859-1", "cp1252"]
    last_err = None
    for enc in encodings:
        try:
            return pd.read_csv(path, encoding=enc, **kwargs)
        except Exception as e:
            last_err = e
            print(f"Failed reading {path} with encoding={enc}: {e}")
    raise last_err

def drop_leaky_and_useless_cols(df):
    # Drop potential leaky columns
    leaky_cols = [col for col in ["status", "target", "Class", "class", "phishing", "is_phishing"] if col in df.columns]
    df = df.drop(columns=leaky_cols, errors="ignore")
    # Drop columns with >80% NaN or constant
    for col in df.columns:
        if df[col].isnull().mean() > 0.8 or df[col].nunique() == 1:
            df = df.drop(columns=[col])
    return df

def balance_classes(df, label_col="label"):
    # Upsample minority class for demo purposes
    class_counts = df[label_col].value_counts()
    if len(class_counts) < 2:
        print("Not enough classes to balance.")
        return df
    min_class = class_counts.idxmin()
    max_class = class_counts.idxmax()
    n_max = class_counts[max_class]
    # Upsample minority
    df_min = df[df[label_col] == min_class]
    df_max = df[df[label_col] == max_class]
    df_min_upsampled = resample(df_min, replace=True, n_samples=n_max, random_state=42)
    df_balanced = pd.concat([df_max, df_min_upsampled]).sample(frac=1, random_state=42).reset_index(drop=True)
    return df_balanced

def preprocess_urls():
    DATA_PATH = Path("data/combined_urls.csv")
    SAVE_DIR = Path("data")
    print(f"Loading {DATA_PATH} ...")
    try:
        df = smart_read_csv(DATA_PATH, low_memory=False)
    except Exception as e:
        print(f"Could not load {DATA_PATH}! Error: {e}")
        return

    print("=== DEBUG DATA LOADING [URL] ===")
    print("Shape:", df.shape)
    print("Columns:", df.columns.tolist())
    print(df.head())
    print(df.info())
    print('Sample "label" values:', df["label"].unique() if "label" in df.columns else "No label column found")

    # Find or create the label column
    if "label" not in df.columns:
        for cand in ["status", "Class", "class", "target"]:
            if cand in df.columns:
                df = df.rename(columns={cand: "label"})
    # Map string labels
    if df["label"].dtype == object:
        df["label"] = df["label"].map({
            "phishing": 1, "legitimate": 0, "legit": 0, "spam": 1, "ham": 0, "fraud": 1, "not_phishing": 0
        })
    # Only keep rows with label 0 or 1
    df = df[df["label"].isin([0, 1])].reset_index(drop=True)
    df["label"] = df["label"].astype(int)

    print("Before balancing, shape:", df.shape)
    print("Label counts:\n", df["label"].value_counts())

    # Drop leaky/useless columns
    df = drop_leaky_and_useless_cols(df)

    # Upsample minority class (for demo/testing)
    df = balance_classes(df, label_col="label")
    print("After balancing, shape:", df.shape)
    print("Label counts:\n", df["label"].value_counts())

    # Keep only 'url' and 'label' columns
    df = df[["url", "label"]]

    # Train/val/test split (stratified)
    train, test = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])
    train, val = train_test_split(train, test_size=0.1, random_state=42, stratify=train["label"])
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    train.to_csv(SAVE_DIR / "url_train.csv", index=False)
    val.to_csv(SAVE_DIR / "url_val.csv", index=False)
    test.to_csv(SAVE_DIR / "url_test.csv", index=False)
    print("URL splits saved to data/")

def preprocess_emails():
    DATA_PATH = Path("data/combined_emails.csv")
    SAVE_DIR = Path("data")
    print(f"Loading {DATA_PATH} ...")
    try:
        df = smart_read_csv(DATA_PATH, low_memory=False)
    except Exception as e:
        print(f"Could not load {DATA_PATH}! Error: {e}")
        return

    print("=== DEBUG DATA LOADING [EMAIL] ===")
    print("Shape:", df.shape)
    print("Columns:", df.columns.tolist())
    print(df.head())
    print(df.info())
    print('Sample "label" values:', df["label"].unique() if "label" in df.columns else "No label column found")

    # Try to find the label column
    label_col = None
    possible_labels = ["label", "Class", "class", "target", "is_phishing", "status", "phishing"]
    for col in possible_labels:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        print("No label column found in email dataset! Please check your CSV.")
        print("Columns found:", df.columns)
        return

    # Rename the label column to 'label'
    if label_col != "label":
        df = df.rename(columns={label_col: "label"})

    # Try to map string labels to 0/1 if needed
    if df["label"].dtype == object:
        value_map = {
            "phishing": 1, "spam": 1, "fraud": 1, "legit": 0, "legitimate": 0, "ham": 0, "not_phishing": 0
        }
        if set(df["label"].unique()).issubset(set(value_map.keys())):
            df["label"] = df["label"].map(value_map)
        else:
            try:
                df["label"] = df["label"].astype(int)
            except Exception as e:
                print("Could not convert label values to int. Please check your label column.")
                print(df["label"].unique())
                return

    # Only keep rows with label 0 or 1 (drop NaN and anything else)
    df = df[df["label"].isin([0, 1])].reset_index(drop=True)
    df["label"] = df["label"].astype(int)

    print("Before balancing, shape:", df.shape)
    print("Label counts:\n", df["label"].value_counts())

    # Drop leaky/useless columns
    df = drop_leaky_and_useless_cols(df)

    # Upsample minority class (for demo/testing)
    df = balance_classes(df, label_col="label")
    print("After balancing, shape:", df.shape)
    print("Label counts:\n", df["label"].value_counts())

    # Try to keep 'body' and 'label', or fallback to first text column if not present
    text_col = None
    for col_candidate in ["body", "text", "Text", "content", "email"]:
        if col_candidate in df.columns:
            text_col = col_candidate
            break
    if text_col is None:
        print("No suitable text column found! Using all columns except label.")
        text_col = [col for col in df.columns if col != "label"][0]
    df = df[[text_col, "label"]]

    train, test = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])
    train, val = train_test_split(train, test_size=0.1, random_state=42, stratify=train["label"])
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    train.to_csv(SAVE_DIR / "email_train.csv", index=False)
    val.to_csv(SAVE_DIR / "email_val.csv", index=False)
    test.to_csv(SAVE_DIR / "email_test.csv", index=False)
    print("Email splits saved to data/")

if __name__ == "__main__":
    preprocess_urls()
    preprocess_emails()