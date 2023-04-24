#!/usr/bin/gnuplot

set terminal postscript eps 'Times-Roman, 40' enhanced color
set datafile separator comma

set style line 1 lt 0 lc rgb "#A92CA5" ps 1 pt 13 lw 7
set style line 2 lt 3 lc rgb "#A92CA5" ps 1 pt 13 lw 7

set style line 3 lt 0 lc rgb "#A6AA2C" ps 1 pt 7 lw 7
set style line 4 lt 4 lc rgb "#A6AA2C" ps 1 pt 7 lw 7

set style line 5 lt 0 lc rgb "#2CA6AA" ps 1 pt 6 lw 7
set style line 6 lt 5 lc rgb "#2CA6AA" ps 1 pt 6 lw 7


set border 3 lw 3
set key at 10, 20 spacing 1 samplen 2 width -2
set ytics 10 nomirror
set mytics 2

set xtics nomirror
set tic scale 1.1 nomirror
set grid ytics

#set yrange
set xrange [0:25]
set yrange [0:20]
set size 1.4,1

set ylabel 'response time (ms)' offset 1.8,-0.5
set xlabel 'throughput (thousands of requests/sec)'

plot 'results/memory_1_sgx_endorser/read.dat' u ($1/1000):2 w linespoints ls 2 title 'Read 50p',\
     '' u ($1/1000):3 w linespoints ls 1 title 'Read 90p',\
     'results/memory_1_sgx_endorser/increment.dat' u ($1/1000):2 w linespoints ls 6 title 'Append 50p',\
     '' u ($1/1000):3 w linespoints ls 5 title 'Append 90p'
#     'results/memory_1_sgx_endorser/create.dat' u ($1/1000):2 w linespoints ls 4 title 'Create 50p',\
#     '' u ($1/1000):3 w linespoints ls 3 title 'Create 90p',\


