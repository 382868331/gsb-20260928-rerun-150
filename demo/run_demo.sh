#!/usr/bin/env bash
# End-to-end demonstration: seal versions, export partial packages, verify with
# an independent verifier, and confirm tampering / splicing / old-version
# replay all fail.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
D="$HERE/output"
mkdir -p "$D"

go build -o "$D/vdx" "$HERE/../cmd/vdx"
VDX="$D/vdx"

printf '%s\n' \
  '"order-001"' '"order-002"' '"same-value"' '"same-value"' '"order-005"' \
  > "$D/v1.jsonl"
printf '%s\n' \
  '"order-001"' '"order-002"' '"same-value"' '"same-value"' '"order-005"' \
  '"order-006"' '"order-007"' > "$D/v2.jsonl"

"$VDX" init --repo "$D/repo" --dataset-id ledger-A
"$VDX" publish --repo "$D/repo" --records "$D/v1.jsonl" | tee "$D/01-v1.txt"
"$VDX" publish --repo "$D/repo" --records "$D/v2.jsonl" | tee "$D/02-v2.txt"
"$VDX" info --repo "$D/repo" | tee "$D/03-info.txt"

ROOT_V1=$(grep -o 'version_id=[0-9a-f]*' "$D/01-v1.txt" | cut -d= -f2)
ROOT_V2=$(grep -o 'version_id=[0-9a-f]*' "$D/02-v2.txt" | cut -d= -f2)
echo "$ROOT_V1" > "$D/root-v1.txt"
echo "$ROOT_V2" > "$D/root-v2.txt"

"$VDX" export --repo "$D/repo" --version 1 --start 2 --end 4 --out "$D/pkg-v1"
"$VDX" export --repo "$D/repo" --version 2 --start 5 --end 7 --out "$D/pkg-v2"

echo "== 1. valid partial package (v1, duplicated-value records at 2,3) =="
"$VDX" verify --bundle "$D/pkg-v1" --root "$ROOT_V1" --dataset-id ledger-A --version 1 \
  --report "$D/report-ok.json"

echo "== 2. old proof cannot be replayed against the new version root =="
if "$VDX" verify --bundle "$D/pkg-v1" --root "$ROOT_V2" --dataset-id ledger-A --version 2; then
  echo "SECURITY FAILURE: v1 proof accepted as v2"; exit 1
else
  echo "rejected as expected"
fi

echo "== 3. cross-version splice: v2 proofs swapped into v1 package header =="
mkdir -p "$D/pkg-splice"
cp "$D/pkg-v1/bundle.json" "$D/pkg-v1/records.jsonl" "$D/pkg-splice/"
cp "$D/pkg-v2/proofs.jsonl" "$D/pkg-splice/proofs.jsonl"
if "$VDX" verify --bundle "$D/pkg-splice" --root "$ROOT_V1" --dataset-id ledger-A --version 1; then
  echo "SECURITY FAILURE: spliced proofs accepted"; exit 1
else
  echo "rejected as expected"
fi

echo "== 4. tampered record byte =="
mkdir -p "$D/pkg-tamper"
cp "$D/pkg-v1/bundle.json" "$D/pkg-v1/proofs.jsonl" "$D/pkg-tamper/"
sed '1s/./X/' "$D/pkg-v1/records.jsonl" > "$D/pkg-tamper/records.jsonl"
if "$VDX" verify --bundle "$D/pkg-tamper" --root "$ROOT_V1" --dataset-id ledger-A --version 1; then
  echo "SECURITY FAILURE: tampering accepted"; exit 1
else
  echo "rejected as expected"
fi

echo "== 5. moved proof (swap first two proof lines) =="
mkdir -p "$D/pkg-moved"
cp "$D/pkg-v1/bundle.json" "$D/pkg-v1/records.jsonl" "$D/pkg-moved/"
awk 'NR==1{first=$0;next}NR==2{print;print first;next}{print}' \
  "$D/pkg-v1/proofs.jsonl" > "$D/pkg-moved/proofs.jsonl"
if "$VDX" verify --bundle "$D/pkg-moved" --root "$ROOT_V1" --dataset-id ledger-A --version 1; then
  echo "SECURITY FAILURE: moved proof accepted"; exit 1
else
  echo "rejected as expected"
fi

echo "== 6. missing record (deleted one line) =="
mkdir -p "$D/pkg-missing"
cp "$D/pkg-v1/bundle.json" "$D/pkg-v1/proofs.jsonl" "$D/pkg-missing/"
head -n 1 "$D/pkg-v1/records.jsonl" > "$D/pkg-missing/records.jsonl"
if "$VDX" verify --bundle "$D/pkg-missing" --root "$ROOT_V1" --dataset-id ledger-A --version 1; then
  echo "SECURITY FAILURE: missing record accepted"; exit 1
else
  echo "rejected as expected"
fi

echo "ALL DEMO CHECKS PASSED; artifacts under $D"
