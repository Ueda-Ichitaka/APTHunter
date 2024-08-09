#!/bin/bash


if [[ `id -u` -ne 0 ]]; then
    echo "Need to be root"
    exit 1
fi

exec_dir=/home/riru/APTHunter/APTHunter/3-Generate-Graph
events_dir=/home/riru/APTHunter/APTHunter/2-LogCore/Log\ Normalizer\ and\ Causality\ Tracker/extracted_events
events_prev_dir=/home/riru/APTHunter/APTHunter/2-LogCore/Log\ Normalizer\ and\ Causality\ Tracker/previous_runs/trace/extracted_events

cd "$exec_dir"


for dir in "$events_dir"/*
do
    echo "$dir"
    sudo ./neo4j-load-forward-tracing-csv.sh "$dir"
done


