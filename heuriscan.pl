#!/usr/bin/perl

#Author: Mathew Long & Joshua Willie
use warnings;
use strict;
my $logdir = '/home';

use File::Find;
use File::Basename;
use POSIX;
use POSIX qw(tzset);
use FileHandle;
use Tie::File;
use Fcntl 'O_RDONLY';
use Cwd 'abs_path';


if ( ! -d "$logdir" ) {
	print "$logdir does not exist, exiting.";
	exit 0;
	}

chomp ( my $webdir = abs_path(<$ARGV[0]>) );

if ( ! -d $webdir ){
	print "$webdir does not exist, exiting";
	exit 0;
	}
	
$ENV{TZ} = 'America/Phoenix'; tzset;


my $foundFile = "$logdir/" . basename($webdir) . "_" . time;
my $grep1 = 'gzinflate\(.{0,15}[a-zA-Z0-9/+=]{250}';
my $grep2 = '([0-9]{1,3},){250}';
my $grep3 = 'base64_decode\(.{0,15}[a-zA-Z0-9/+=]{250}';
my $grep4 = 'HTTP_USER_AGENT.*Yandex';
my $grep5 = '[Tt][iI][tT][lL][eE]>.{0,50}[hH][aA][cC][kK][eE][dD] [bB][yY]';
my $grep6 = 'fsockopen\(.udp';
my $grep7 = '[Tt][iI][tT][lL][eE]>.{0,50}[Bb]ank.{0,40}([lL]ogin|[pP]assword).{0,90}</[Tt][iI][tT][lL][eE]';
my $grep8 =  'mail\(\$email\[\$i\].{1,600}i\+\+';
my $grep9 =  'objFSObject\.CreateTextFile';


my $grepTerm = "$grep1|$grep2|$grep3|$grep4|$grep5|$grep6|$grep7|$grep8|$grep9";

if ( -e "$foundFile" )  {

        open FOUNDFILE, "<", "$foundFile";

        my $complete = grep /Scan complete/, <FOUNDFILE>;

        close FOUNDFILE;

        if ($complete ne '') {

                my $age = -M $foundFile;

                if ($age > 1) {

                        unlink($foundFile);

                } else {

                        exit 0;

                }

        }

} else {

open FOUNDLOG, ">", "$foundFile";

FOUNDLOG->autoflush(1);

print FOUNDLOG (strftime "Scan started: %H:%M %m-%d-%Y\n", localtime);

find ({ wanted => \&WantedFiles }, $webdir);

print FOUNDLOG (strftime "Scan complete: %H:%M %m-%d-%Y\n", localtime);

close FOUNDLOG;

}

sub WantedFiles {

my $filePath = "$File::Find::dir/$_";

return unless ( -f "$filePath" );

if ( $filePath =~ /(\.(tar|zip|gzip|tar\.gz|7zip|rar)$)/ ) { return; }

if ( -s "$filePath" > 104857600 ) { print FOUNDLOG "$filePath: File larger than 100MB DETECTED\n"; return ; }
elsif ( -s "$filePath" > 8388608 ) { return; }

tie my @array, 'Tie::File', $filePath, mode => O_RDONLY, memory => 3_000_000  or return;

my $darray =  join( ', ', @array);
return unless ($darray =~ m/$grepTerm/);

if ($darray =~ /$grep1/) { print FOUNDLOG "$filePath: LONG gzinflate DETECTED\n"; return ; }
elsif ($darray =~ /$grep2/) { print FOUNDLOG "$filePath: Unicode RegEx DETECTED\n"; return ; }
elsif ($darray =~ /$grep3/) { print FOUNDLOG "$filePath: LONG base64_decode DETECTED\n"; return ; }
elsif ($darray =~ /$grep4/) { print FOUNDLOG "$filePath: Yandex Checker DETECTED\n"; return ; }
elsif ($darray =~ /$grep5/) { print FOUNDLOG "$filePath: Defaced Page DETECTED\n"; return ; }
elsif ($darray =~ /$grep6/) { print FOUNDLOG "$filePath: PHP UDP fsockopen DETECTED\n"; return ; }
elsif ($darray =~ /$grep8/) { print FOUNDLOG "$filePath: Mass Mailer DETECTED\n"; return ; }
elsif ($darray =~ /$grep7/) { print FOUNDLOG "$filePath: Bank Phishing Page DETECTED\n"; return ; }
elsif ($darray =~ /$grep9/) { print FOUNDLOG "$filePath: Possible VB Shell DETECTED\n"; return ; }

}
exit 0;

