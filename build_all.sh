#!/bin/bash

OUTPUT_DIR=build
mkdir -p $OUTPUT_DIR

PLATFORMS=(
  "linux/amd64"
)

for PLATFORM in "${PLATFORMS[@]}"
do
  GOOS=${PLATFORM%/*}
  GOARCH=${PLATFORM#*/}
  OUTPUT_NAME="zandoli-${GOOS}-${GOARCH}"
  [[ "$GOOS" == "windows" ]] && OUTPUT_NAME+=".exe"

  echo "Building for $GOOS/$GOARCH..."
  env GOOS=$GOOS GOARCH=$GOARCH go build -o "$OUTPUT_DIR/$OUTPUT_NAME" ./cmd
done

