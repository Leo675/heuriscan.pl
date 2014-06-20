heuriscan
=========
Usage:
heuriscan.pl /path/to/directory

Recursive when target is a directory. Scanning individual files works too.

Description:
--------
Malware heuristics scanner tailored for scanning hacked websites

Scans are saved to a log file in $logdir for review. Standard output is intended to be silent unless errors are encountered.

Configuration:
--------
Change line 6 to a directory where you want the log files stored:

my $logdir = '/home';

Log file names will be = basename($webdir) . "_" . time;


Regex patterns detected:
--------
'gzinflate\(.{0,15}[a-zA-Z0-9/+=]{250}'
'([0-9]{1,3},){250}'
'base64_decode\(.{0,15}[a-zA-Z0-9/+=]{250}'
'HTTP_USER_AGENT.*Yandex'
'[Tt][iI][tT][lL][eE]>.{0,50}[hH][aA][cC][kK][eE][dD] [bB][yY]'
'fsockopen\(.udp'
'[Tt][iI][tT][lL][eE]>.{0,50}[Bb]ank.{0,40}([lL]ogin|[pP]assword).{0,90}</[Tt][iI][tT][lL][eE]'
'mail\(\$email\[\$i\].{1,600}i\+\+'
'objFSObject\.CreateTextFile'

I will be updating these patterns soon as I have some better ones, but they need to be tested first.

Compatability:
--------

Tested on perl 5.8.8 and newer

Perl modules used:

use warnings;
use strict;
use File::Find;
use File::Basename;
use POSIX;
use POSIX qw(tzset);
use FileHandle;
use Tie::File;
use Fcntl 'O_RDONLY';
use Cwd 'abs_path';
