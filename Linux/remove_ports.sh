#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root."
   exit 1
fi

# --- CONFIGURATION ---
ALLOWED_PORTS=(22 80 443)

echo "Checking for unrecognized open ports..."

open_ports=$(ss -lntup | grep 'LISTEN' | awk '{print $5}' | cut -d: -f2 | sort -u)

for port in $open_ports; do
    # Skip empty strings
    [[ -z "$port" ]] && continue

    # Check if the port is in the whitelist
    is_allowed=false
    for allowed in "${ALLOWED_PORTS[@]}"; do
        if [[ "$port" == "$allowed" ]]; then
            is_allowed=true
            break
        fi
    done

    if [ "$is_allowed" = true ]; then
        echo "[SAFE] Port $port is on the whitelist."
    else
        echo "[!] UNRECOGNIZED PORT DETECTED: $port"
        
        # Find the PID using this port
        # lsof -t gives just the PID
        pid=$(lsof -t -i :"$port")

        if [ -n "$pid" ]; then
            process_name=$(ps -p "$pid" -o comm=)
            echo "    -> Found Process: $process_name (PID: $pid)"
            
            # KILL the process
            echo "    -> Terminating PID $pid..."
            kill -9 "$pid"
            echo "    -> Port $port should now be closed."
        else
            echo "    -> Could not identify PID (might be a kernel process or already closed)."
        fi
    fi
done

echo "Scan complete."