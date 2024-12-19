#!/bin/bash

# Script to handle GET requests on localhost at port 4091

PORT=4091

# Function to handle incoming requests
handle_request() {
    local request=$1
    echo "Received request: $request"

    # Prepare HTTP response
    local response="HTTP/1.1 200 OK\r\n"
    response+="Content-Type: text/plain\r\n"
    response+="Connection: close\r\n\r\n"
    response+="Hello, World! You sent: $request"

    # Send the response
    echo -e "$response"
}

# Start the server
echo "Starting server on port $PORT..."
while true; do
    # Listen on the specified port
    {
        read -r request
        handle_request "$request"
    } | nc -l -p $PORT
done

