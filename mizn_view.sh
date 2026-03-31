#!/bin/bash

# Define the database file
DB_FILE="miznd_telemetry.db"

# Check if sqlite3 is installed
if ! command -v sqlite3 &> /dev/null; then
    echo "Error: sqlite3 is not installed. Please install it first."
    exit 1
fi

# Check if the database exists
if [ ! -f "$DB_FILE" ]; then
    echo "Error: Cannot find $DB_FILE in the current directory."
    exit 1
fi

show_menu() {
    clear
    echo "==================================================="
    echo "            MIZN Network Telemetry Viewer          "
    echo "==================================================="
    echo "1)  Live Tail (Latest 20 Connections)"
    echo "2)  Top Talkers (Processes by Bandwidth)"
    echo "3)  Top Destinations (Most visited SNI/Domains)"
    echo "4)   Continuous Monitor (Auto-refreshing Dashboard)"
    echo "q) Quit"
    echo "==================================================="
}

read_choice() {
    local choice
    read -p "Select an option [1-4, q]: " choice
    case $choice in
        1)
            clear
            echo "--- Latest 20 Connections ---"
            sqlite3 -header -column "$DB_FILE" "
            SELECT datetime(ts, 'unixepoch', 'localtime') AS Time,
                   pid AS PID,
                   process AS Process,
                   protocol AS Proto,
                   sni AS Destination,
                   bytes_delta AS Bytes
            FROM flow_events ORDER BY ts DESC LIMIT 20;"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        2)
            clear
            echo "--- Top Processes by Bandwidth ---"
            sqlite3 -header -column "$DB_FILE" "
            SELECT process AS Process,
                   COUNT(*) AS Connections,
                   SUM(bytes_delta) AS Total_Bytes
            FROM flow_events
            GROUP BY process ORDER BY Total_Bytes DESC LIMIT 15;"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        3)
            clear
            echo "--- Top Destinations (SNI) ---"
            sqlite3 -header -column "$DB_FILE" "
            SELECT sni AS Domain,
                   COUNT(*) AS Hits,
                   SUM(bytes_delta) AS Total_Bytes
            FROM flow_events
            WHERE sni IS NOT NULL AND sni != ''
            GROUP BY sni ORDER BY Hits DESC LIMIT 15;"
            echo ""
            read -p "Press Enter to return to menu..."
            ;;
        4)
            clear
            echo "Starting Real-Time Dashboard. Press Ctrl+C to exit to menu."
            sleep 1.5
            # Uses 'watch' to execute the query every 2 seconds for a live feed
            watch -n 2 -t "echo '=== MIZN Live Telemetry (Updates every 2s) ===' && echo '' && sqlite3 -header -column \"$DB_FILE\" \"SELECT datetime(ts, 'unixepoch', 'localtime') AS Time, process AS Process, protocol AS Proto, sni AS Destination, bytes_delta AS Bytes FROM flow_events ORDER BY ts DESC LIMIT 25;\""
            ;;
        q|Q)
            clear
            echo "Exiting MIZN Viewer..."
            exit 0
            ;;
        *)
            echo "Invalid option."
            sleep 1
            ;;
    esac
}

# Main loop
while true; do
    show_menu
    read_choice
done
