#!/usr/local/bin/perl
#Original authors: Mathew Long & Joshua Willie
#Continued development: Mathew Long
use warnings;
use strict;

############### Essential dependency configurations ###############

#PATH TO LOG DIR
my $logDir = '/var/log/clamlog';

############### End configurations ###############

#Dependency check
my $depFail;
if (! -e $logDir) { $depFail .= "logDir: $logDir NOT FOUND\n"; }
if ($depFail) { print "\nDEPENDANCY ERROR:\n$depFail\nExiting..."; exit 0;}

use File::Find;
use File::Copy;
use File::Basename;
use POSIX;
use POSIX qw(tzset);
use FileHandle;
use Tie::File;
use Fcntl 'O_RDONLY';
use Cwd 'abs_path';

#set time zone
$ENV{TZ} = 'America/Phoenix'; tzset;

chomp ( my $username = <$ARGV[0]> );

chomp ( my $webdir = abs_path(<$ARGV[0]>) );

if ( ! -d $webdir ){
	print "$webdir does not exist, exiting";
	exit 0;
}

my $foundFile = "$logDir/" . basename($webdir) . "_" . time;


#Removes log file older than 12 hours and aborts scan if it is newer
if ( -e "$foundFile" )  {
	open FOUNDFILE, "<", "$foundFile";
	my $complete = grep /Scan complete/, <FOUNDFILE>;
	close FOUNDFILE;
	if ($complete eq '') { exit 0; }
	elsif ($complete ne '') {
		my $age = -M $foundFile;
		if ($age > '.5') {
		unlink($foundFile);
		}
		else { exit 0; }
	}
}

#LONG gzinflate
my $heuri01 = 'gzinflate\(.{0,15}[a-zA-Z0-9/+=]{250}';
#LONG Unicode RegEx
my $heuri02 = '([0-9]{1,3},){250}';
#LONG base64_decode
my $heuri03 = q%(base64_decode|\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5F\\\\x64\\\\x65\\\\x63\\\\x6F\\\\x64\\\\x65)(\(|\\\\x28).{0,15}[a-zA-Z0-9/+=]{250}%;
#Yandex checker
my $heuri04 = 'HTTP_USER_AGENT.{0,30}Yandex';
#Defaced Page
my $heuri05 = '<\s{0,10}[Tt][iI][tT][lL][eE]\s{0,10}>.{0,50}[hH][aA][cC][kK][eE][dD]\s{0,}[bB][yY]';
#UDP Flood
my $heuri06 = 'fsockopen\(.udp';
#Bank Phishing Page
my $heuri07 = '[Tt][iI][tT][lL][eE]>.{0,50}([Bb]ank|Twitter|Facebook).{0,40}([lL]og\s?[Ii]n|[pP]assword).{0,90}</[Tt][iI][tT][lL][eE]';
#Mass Mailer
my $heuri08 =  'mail\(\$email\[\$i\].{1,600}i\+\+';
#Possible VB Shell
my $heuri09 =  'objFSObject\.CreateTextFile';
#LONG Hex Obfuscation RegEx
my $heuri10 = '([a-zA-Z0-9]{1,2}[,:]){250}';
#Escape Encoded RegEx
my $heuri11 = '(%[0-9a-zA-Z]{2}){80,}';

#Build final grep expression
my $heuriTerm = "$heuri01|$heuri02|$heuri03|$heuri04|$heuri05|$heuri06|$heuri07|$heuri08|$heuri09|$heuri10|$heuri11";


#Open log of detections and enable incremental writing
open FOUNDLOG, ">", $foundFile;
FOUNDLOG->autoflush(1);

#Scan start timestamp
print FOUNDLOG (strftime "Scan started: %H:%M %m-%d-%Y\n", localtime);

#Main scanning subroutine &WantedFiles
find ({ wanted => \&WantedFiles }, $webdir);

#Scan complete timestamp
print FOUNDLOG (strftime "Scan complete: %H:%M %m-%d-%Y\n", localtime);

close FOUNDLOG;


sub WantedFiles {

my $filePath = "$File::Find::dir/$_";

#return if not a file
return unless ( -f "$filePath" );

#return if archive
if ( $filePath =~ /(\.(tar|zip|gzip|tar\.gz|7zip|rar)$)/ ) { return; }

#skip if larger than 20MB and log if larger than 100MB
if ( -s "$filePath" > 104857600 ) { print FOUNDLOG "$filePath: File larger than 100MB DETECTED\n"; return ; }
elsif ( -s "$filePath" > 8388608 ) { return; }

#tie file to array
tie my @array, 'Tie::File', $filePath, mode => O_RDONLY, memory => 3_000_000  or return;

#join file to all one line
my $darray =  join( '', @array);

#check if matches any, then enters elsif logic to narrow the detection
return unless ($darray =~ m/$heuriTerm/);

#Automatic malware definitions for gzinflate by sub &autoMal
if ($darray =~ /$heuri01/) { print FOUNDLOG "$filePath: LONG gzinflate DETECTED\n"; return; }
elsif ($darray =~ /$heuri10/) { print FOUNDLOG "$filePath: LONG Hex Obfuscation DETECTED\n"; return; }
elsif ($darray =~ /$heuri02/) { print FOUNDLOG "$filePath: LONG Unicode DETECTED\n"; return; }
elsif ($darray =~ /$heuri11/) { print FOUNDLOG "$filePath: Escape Encoded DETECTED\n"; return; }
elsif ($darray =~ /$heuri03/) { print FOUNDLOG "$filePath: LONG base64_decode DETECTED\n"; return;	}
elsif ($darray =~ /$heuri04/) { print FOUNDLOG "$filePath: Yandex Checker DETECTED\n"; return; }
elsif ($darray =~ /$heuri05/) { print FOUNDLOG "$filePath: Defaced Page DETECTED\n"; return; }
elsif ($darray =~ /$heuri06/) { print FOUNDLOG "$filePath: PHP UDP fsockopen DETECTED\n"; return; }
elsif ($darray =~ /$heuri08/) { print FOUNDLOG "$filePath: Mass Mailer DETECTED\n"; return; }
elsif ($darray =~ /$heuri07/) { print FOUNDLOG "$filePath: Bank Phishing Page DETECTED\n"; return; }
elsif ($darray =~ /$heuri09/) { print FOUNDLOG "$filePath: Possible VB Shell DETECTED\n"; return; }
}

exit 0;
