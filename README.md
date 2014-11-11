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

my $logDir = '/var/log/clamlog';

Log file names will be: <folder or file name>_<unix time>

PCRE patterns detected:
--------
gzinflate longer than 250 characters
'gzinflate\(.{0,15}[a-zA-Z0-9/+=]{250}'

Unicode longer than 250 characters
'([0-9]{1,3},){250}'

base64_decode longer than 250 characters
q%(base64_decode|\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5F\\\\x64\\\\x65\\\\x63\\\\x6F\\\\x64\\\\x65)(\(|\\\\x28).{0,15}[a-zA-Z0-9/+=]{250}%

Yandex checker
'HTTP_USER_AGENT.{0,30}Yandex';

Defaced Page
'<\s{0,10}[Tt][iI][tT][lL][eE]\s{0,10}>.{0,50}[hH][aA][cC][kK][eE][dD]\s{0,}[bB][yY]'

UDP Flood
'fsockopen\(.udp'

Phishing Page
'[Tt][iI][tT][lL][eE]>.{0,50}([Bb]ank|Twitter|Facebook).{0,40}([lL]og\s?[Ii]n|[pP]assword).{0,90}</[Tt][iI][tT][lL][eE]'

Mass Mailer
'mail\(\$email\[\$i\].{1,600}i\+\+'

Possible VB Shell
'objFSObject\.CreateTextFile'

Hex Obfuscation longer than250 characters
'([a-zA-Z0-9]{1,2}[,:]){250}'

Escape Encoded RegEx
'(%[0-9a-zA-Z]{2}){80,}'

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
