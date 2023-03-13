if [ "$1" !=  "" ] && [ "$1" !=  "fast" ] && [ "$1" !=  "slow" ]; then echo 'error: '$1' is not a valide option (fast, slow or empty are valide. Default is slow)' ; exit; fi; if [ "$1" ==  "fast" ]; then
    # my slow script
    echo "Start of the script2 in slow mode"
    sleep 30
    echo "End of script2 in slow mode"
else
    # my fast script
    echo "Start of the script2 in fast mode"
    sleep 60
    echo "End of script2 in fast mode"
fi
