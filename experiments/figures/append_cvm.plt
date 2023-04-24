#!/usr/bin/gnuplot

set terminal postscript eps 'Times-Roman, 40' enhanced color
set datafile separator comma

set style line 1 lt 0 lc rgb "#A92CA5" ps 1 pt 13 lw 7
set style line 2 lt 3 lc rgb "#A92CA5" ps 1 pt 13 lw 7

set style line 3 lt 0 lc rgb "#2CAA30" ps 1 pt 7 lw 7
set style line 4 lt 4 lc rgb "#2CAA30" ps 1 pt 7 lw 7


set border 3 lw 3
set key at 40, 100 spacing 1 samplen 2 width -2
set ytics 10 nomirror
set mytics 2

set xtics nomirror
set tic scale 1.1 nomirror
set grid ytics

#set yrange
set xrange [0:60]
set yrange [0:100]
set size 1.4,1

set ylabel 'response time (ms)' offset 1.8,-0.5
set xlabel 'throughput (thousands of requests/sec)'

plot 'results/memory_3_endorsers/increment.dat' u ($1/1000):2 w linespoints ls 2 title 'Memory 50p',\
     '' u ($1/1000):3 w linespoints ls 1 title 'Memory 90p',\
     'results/table_3_endorsers/increment.dat' u ($1/1000):2 w linespoints ls 4 title 'Azure Table 50p',\
     '' u ($1/1000):3 w linespoints ls 3 title 'Azure Table 90p'


