if [ "$1" !=  "" ] && [ "$1" !=  "fast" ] && [ "$1" !=  "slow" ]; then echo 'error: '$1' is not a valide option (fast or empty is valide)' ; exit; fi
if [ "$1" ==  "fast" ]
then
    echo "Start of the script in fast mode"
    sleep 500
    echo "End of script in fast mode"
else
    echo "Start of the script in slow mode"
    sleep 1200
    echo "End of script in slow mode"
fi
