#!/bin/bash
[ -e vitima_input ] && rm vitima_input
touch vitima_input
echo -e "teste 1 2 3 4 5 6 tcp hijacking" > vitima_input;

#./simple-client 10.0.1.10 8000 < vitima_input
./simple-client 10.0.1.10 8000
