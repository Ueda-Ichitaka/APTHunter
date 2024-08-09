#!/bin/bash


if [[ `id -u` -ne 0 ]]; then
    echo "Need to be root"
    exit 1
fi

exec_dir=/home/riru/APTHunter/APTHunter/3-Generate-Graph
events_dir=/home/riru/APTHunter/APTHunter/2-LogCore/Log\ Normalizer\ and\ Causality\ Tracker/extracted_events
events_prev_dir=/home/riru/APTHunter/APTHunter/2-LogCore/Log\ Normalizer\ and\ Causality\ Tracker/previous_runs/trace/extracted_events

cd "$exec_dir"

# for dir in "$subjects_dir"/*
# do
#     echo "$dir"
#
#     sudo ./neo4j-load-csv.sh "$dir"
# done


## forward csv einmal vorwärts einmal rückwärts importiert. also quasi original + import forward tracing
for dir in "$events_prev_dir"/*
do
    echo "$dir"
    sudo ./neo4j-load-forward-tracing-csv.sh "$dir"
done

#
# ## original
# for dir in "$events_dir"/*
# do
#     echo "$dir"
#     sudo ./neo4j-load-csv-2.sh "$dir"
# done
#
#
# ## original, nur import richtung forward umgedreht, also quasi import forward tracing
# for dir in "$events_dir"/*
# do
#     echo "$dir"
#     sudo ./neo4j-load-csv-3.sh "$dir"
# done


