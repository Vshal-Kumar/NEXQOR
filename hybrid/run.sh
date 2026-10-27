#!/bin/bash
# hybrid/run.sh — Launch Hybrid Multi-Client Server, Receiver, and Transmitter Terminals

if command -v gnome-terminal >/dev/null 2>&1; then
    gnome-terminal --title="Hybrid Server" -- bash -c "./server; exec bash"
    sleep 0.5
    gnome-terminal --title="Hybrid Server RX Terminal" -- bash -c "./server_rx; exec bash"
    sleep 0.5
    gnome-terminal --title="Hybrid Server TX Terminal" -- bash -c "./server_tx; exec bash"
elif command -v xterm >/dev/null 2>&1; then
    xterm -title "Hybrid Server" -e "./server; bash" &
    sleep 0.5
    xterm -title "Hybrid Server RX Terminal" -e "./server_rx; bash" &
    sleep 0.5
    xterm -title "Hybrid Server TX Terminal" -e "./server_tx; bash" &
else
    echo "No graphical terminal emulator found. Starting server in background..."
    ./server &
    SRV_PID=$!
    echo "Server running with PID $SRV_PID."
    echo "Run './server_rx' and './server_tx' in separate shells."
fi
