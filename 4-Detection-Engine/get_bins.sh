#!/bin/bash


data_home="/home/riru/APTHunter/APTHunter/2-LogCore/Log Normalizer and Causality Tracker/"
cd "$data_home/extracted_events"


cat "$data_home/bins_foothold.txt" | while read line || [[ -n $line ]];
do
    count=$(grep -Rnw $line | wc -l)
    if [ $count -gt 0 ]
    then
        echo -n "|$line"
    fi
done

