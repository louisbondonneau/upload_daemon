if [ "$1" !=  "" ] && [ "$1" !=  "fast" ] && [ "$1" !=  "slow" ]; then echo 'error: '$1' is not a valide option (fast or empty is valide)' ; exit; fi

if [ "$1" ==  "fast" ]
then
    echo "Start of the script5 in fast mode"
    sleep 300
    echo "End of script5 in fast mode"
    ls /blabla
else
    echo "Start of the script5 in slow mode"
    sleep 1200
    echo "End of script5 in slow mode"
    ls /blabla
fi
