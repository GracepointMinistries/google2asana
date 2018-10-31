#!/bin/bash
aws lambda invoke \
--invocation-type Event \
--function-name google2asana \
--region us-west-1 \
outputfile.txt
rm outputfile.txt