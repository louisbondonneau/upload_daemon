if [ "$1" !=  "" ] && [ "$1" !=  "fast" ] && [ "$1" !=  "slow" ]; then echo 'error: '$1' is not a valide option (fast, slow or empty are valide. Default is slow)' ; exit; fi; if [ "$1" ==  "fast" ]; then
    echo "Start of the script6 in fast mode"
    sleep 30
    echo "End of script6 in fast mode"
    # ls /blabla
else
    echo "Start of the script6 in slow mode"
    sleep 60
    echo "End of script6 in slow mode"
fi
