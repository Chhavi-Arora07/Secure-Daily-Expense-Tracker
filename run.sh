#!/usr/bin/env bash
# ./run.sh         starts the application
# ./run.sh check   runs the security verification checks
cd "$(dirname "$0")"
if [ "$1" = "check" ]; then exec java -cp "out:lib/*" expensetracker.SecurityCheck; fi
exec java -cp "out:lib/*" expensetracker.Main
