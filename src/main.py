import os

def run_all():
    print("=== PREPROCESSING ===")
    os.system("python src/preprocess_all.py")
    print("=== TRAINING ===")
    os.system("python src/train_model.py")
    print("=== DONE ===")

if __name__ == "__main__":
    run_all()