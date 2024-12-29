#!/bin/bash -e
THREADS=64
FILES=500000
DIRS=500000

function bench {
        op=$1
        echo "Running $op:"
        hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op $*
}

bench create      -threads $THREADS -files $FILES
bench mkdirs      -threads $THREADS -dirs $DIRS
bench open        -threads $THREADS -files $FILES
bench delete      -threads $THREADS -files $FILES
bench fileStatus  -threads $THREADS -files $FILES
bench rename      -threads $THREADS -files $FILES
bench clean