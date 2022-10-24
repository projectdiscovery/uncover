#!/bin/bash

echo "::task~> Clean up & Build binaries files"
rm integration-test uncover 2>/dev/null
cd ../cmd/uncover
go build
mv uncover ../../integration-tests/uncover
cd ../../integration-tests
go build
echo "::done::"
echo "::task~> Run integration test"
./integration-tests
echo "::done::"
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
