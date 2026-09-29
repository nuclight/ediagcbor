#!/usr/local/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use EDNTest;

EDNTest::run_csv("$FindBin::Bin/level-shifter.csv");
