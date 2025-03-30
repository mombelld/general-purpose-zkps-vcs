#!/bin/bash
# Run 'conda activate sage' in command line before executing this

MIN=2
MAX=17

for (( t = $MIN ; t <= $MAX ; t+=1 ));
do
sage generate_params_poseidon.sage 1 0 256 $t 5 128 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
done