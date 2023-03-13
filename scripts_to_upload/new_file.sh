if [ "$1" !=  "" ] && [ "$1" !=  "fast" ] && [ "$1" !=  "slow" ]; then echo 'error: '$1' is not a valide option (fast, slow or empty are valide. Default is slow)' ; exit; fi; if [ "$1" ==  "fast" ]; then
    echo "Start example of the script in fast mode"
    sleep 30
    echo "End example of script in fast mode"
else
    echo "Start example of the script in slow mode"
    sleep 60
    echo "End example of script in slow mode"
fi
