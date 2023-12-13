#!/bin/bash

# Set your API endpoint and credentials
API_ENDPOINT="https://fetherstill-api-c4fa2236c2a6.herokuapp.com"
EMAIL="user@privatecloud.ca"
PASSWORD="user"

# Function to log in and get a token
get_token() {
    local response=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" "$API_ENDPOINT/login")
    local token=$(jq -r '.token' <<<"$response")
    echo "$token"
}

# Function to upload a file
upload_file() {
    local token="$1"
    local folder_path="files"
    local file_name="test.txt"

    if [ -e "$folder_path/$file_name" ]; then
        local response=$(curl -s -X POST -H "Authorization: Bearer $token" -F "file=@$folder_path/$file_name" "$API_ENDPOINT/upload")
        local http_status=$(jq -r '.status' <<<"$response")

        if [ "$http_status" == "true" ]; then
            echo "File $file_name sent to $API_ENDPOINT/upload"
        else
            echo "File $file_name upload failed. HTTP Status Code: $http_status"
        fi
    else
        echo "File $file_name not found in $folder_path"
    fi
}

# Main script
while true; do
    token=$(get_token)
    if [ -n "$token" ]; then
        upload_file "$token"
    else
        echo "Token not found in the API response."
    fi

    # Sleep for 5 minutes (300 seconds)
    echo "Sleeping for 5 minutes"
    sleep 300
done
