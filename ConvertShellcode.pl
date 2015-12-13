#!/usr/bin/perl
# Perl - v: 5.16.3
#------------------------------------------------------------------------------#
# Tool name   : ConvertShellCode
# Website     : http://le-tools.com/
# GitHub		  : https://github.com/arioux/ConvertShellcode
# Description : ConvertShellcode take Shellcode as input and produce list of instructions
#               in assembly language
# Creation    : 2009-05-06
# Modified    : 2015-12-12 (Licensed under GPLv3)
my $VERSION   = "3.0";
# Author      : Alain Rioux (admin@le-tools.com)
#
# Copyright (C) 2009-2015  Alain Rioux (le-tools.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------------------#

use strict;
use warnings;
use Disassemble::X86;
use Disassemble::X86::FormatText;
# shellcode (sample) =  "\x5e\x31\xc0\xb0\x24\xcd\x80\xb0\x24\xcd\x80\xb0\x58\xbb\xad" .
#                       "\xde\xe1\xfe\xb9\x69\x19\x12\x28\xba\x67\x45\x23\x01\xcd\x80";

my  $notice  = "\nConvertShellcode $VERSION\n";
    $notice .= "***********************************************************************\n";
    $notice .= "Copyright (C) 2009-2015 Alain Rioux (le-tools.com). All rights reserved.\n\n";
    $notice .= "This program is free software: you can redistribute it and/or modify\n";
    $notice .= "it under the terms of the GNU General Public License as published by\n";
    $notice .= "the Free Software Foundation, either version 3 of the License, or\n";
    $notice .= "(at your option) any later version.\n\n";
    $notice .= "This program is distributed in the hope that it will be useful,\n";
    $notice .= "but WITHOUT ANY WARRANTY; without even the implied warranty of\n";
    $notice .= "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n";
    $notice .= "GNU General Public License for more details.\n\n";
    $notice .= "You should have received a copy of the GNU General Public License\n";
    $notice .= "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n";
    $notice .= "***********************************************************************\n\n";

if ($ARGV[0] and
    (($ARGV[0] =~ /^(?:\\x[0-9A-Fa-f]{2})+$/i) or
     ($ARGV[0] =~ /^(?:(?:[\%\\]u|\&\#x)[0-9a-fA-F]{4})+$/i) or
     ($ARGV[0] =~ /^(?:\%[0-9a-fA-F]{2})+$/i))) {
  my $txt = $ARGV[0];
  $txt =~ s/\\x([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
  $txt =~ s/(?:[\%\\]u|\&\#x)([0-9a-fA-F]{2})([0-9a-fA-F]{2})/pack("CC", hex($2), hex($1))/ige;
  $txt =~ s/\%([0-9a-fA-F]{2})/pack("C", hex($1))/ige;
  my $d = Disassemble::X86->new(text => $txt, format => "Text",);
  print $notice;
  print "Assembly language source code :\n***************************************\n";
  while (defined( my $op = $d->disasm() )) { printf "%08x  %s\n", $d->op_start(), $op; }
} else {
  print $notice;
  print "Correct usage is : $0 [Shellcode]\n";
}
