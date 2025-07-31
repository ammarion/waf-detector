#!/bin/bash

# Test basic request to adobe.com
echo "Testing basic GET request to adobe.com..."
curl -s -o response.html -w "Status: %{http_code}\nSize: %{size_download} bytes\n" https://adobe.com

echo -e "\nFirst 500 characters of response:"
head -c 500 response.html

echo -e "\n\nResponse size:"
wc -c response.html

rm -f response.html