import csv
from collections import Counter
from pathlib import Path

DATA_PATH = Path(
    "data/raw/Train_Test_datasets/"
    "Train_Test_Network_dataset/train_test_network.csv"
)

with DATA_PATH.open(
    encoding="utf-8-sig",
    newline=""
) as file:

    reader = csv.DictReader(file)
    columns = reader.fieldnames or []

    print("\n=== DATASET SCHEMA ===")
    print(f"Number of features/columns: {len(columns)}")

    for column in columns:
        print(column)

    targets = {
        name: Counter()
        for name in ("label", "type")
        if name in columns
    }

    missing = Counter()
    total_rows = 0

    for row in reader:
        total_rows += 1

        for name, counts in targets.items():
            counts[row.get(name, "")] += 1

        for name, value in row.items():
            if name is not None and (
                value is None or not value.strip()
            ):
                missing[name] += 1

print(f"\nTotal records: {total_rows:,}")

for name, counts in targets.items():
    print(f"\n=== {name.upper()} DISTRIBUTION ===")

    for value, count in counts.most_common():
        percentage = count / total_rows * 100
        print(f"{value}: {count:,} ({percentage:.2f}%)")

print("\n=== COLUMNS WITH MISSING VALUES ===")

for name, count in missing.most_common(15):
    print(f"{name}: {count:,}")