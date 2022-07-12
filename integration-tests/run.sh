#!/bin/bash

echo "::group::Build uncover"
rm integration-test uncover 2>/dev/null
cd ../cmd/uncover
go build
mv uncover ../../integration-tests/uncover
echo "::endgroup::"
echo "::group::Build uncover integration-test"
cd ../integration-test
go build
mv integration-test ../../integration-tests/integration-test 
cd ../../integration-tests
echo "::endgroup::"
./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi

