#!/bin/bash
go get
GOOS=linux go build asanaSync.go
zip deployment.zip asanaSync key.pem
aws lambda update-function-code --function-name google2asana --zip-file fileb://deployment.zip --publish
rm deployment.zip