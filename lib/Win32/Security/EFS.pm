package Win32::Security::EFS;

use strict;
use warnings;

use Win32::API ();
use File::Spec ();

use vars qw/$VERSION/;
$VERSION = '0.05';

=head1 NAME

Win32::Security::EFS - Perl interface to functions that assist in working
with EFS (Encrypted File System) under Windows plattforms.

=head1 SYNOPSIS

	use Win32::Security::EFS;
	
	if(Win32::Security::EFS->supported()) {
		Win32::Security::EFS->encrypt('some/file');
		Win32::Security::EFS->decrypt('some/file');
	}




=head1 DESCRIPTION

The Encrypted File System, or EFS, was introduced in version 5 of NTFS to 
provide an additional level of security for files and directories. It 
provides cryptographic protection of individual files on NTFS volumes 
using a public-key system. Typically, the access control to file and 
directory objects provided by the Windows security model is sufficient to 
protect unauthorized access to sensitive information. However, if a laptop 
containing sensitive data is lost or stolen, the security protection of 
that data may be compromised. Encrypting the files increases security in 
this scenario.

=head2 METHODS

=over 4

=item B<supported()>

Returns I<true> iff the underlaying filesystem supports EFS

=cut

sub supported {
    require Win32;        

    my (undef, $flags, undef) = Win32::FsType();
    return ( $flags & 0x00020000 ) > 0;
}

=item B<encrypt($filename)>

The I<encrypt> function encrypts a file or directory. All data streams in a file are encrypted. 
All new files created in an encrypted directory are encrypted.

=cut

sub encrypt {
	my ($self, $filename) = @_;	
	my $func = import_api('advapi32', 'EncryptFile', 'P', 'I');
	die "Could not import API EncryptFile: $!" unless defined $func;
	return $func->Call( File::Spec->canonpath( $filename ) );
}

=item B<decrypt($filename)>

The I<decrypt> function decrypts an encrypted file or directory.

=cut

sub decrypt {                
	my ($self, $filename) = @_;	
	my $func = import_api('advapi32', 'DecryptFile', 'PN', 'I');
	die "Could not import API DecryptFile: $!" unless defined $func;
	return $func->Call( File::Spec->canonpath( $filename ), 0 );
}

{
	my %api = ();
	sub import_api {
		my ($lib, $func, $params, $retval) = @_;
		my $key = join "_", map { uc } ($lib, $func, $params, $retval);
		
		$api{$key} = Win32::API->new($lib, $func, $params, $retval)
		   unless exists $api{$key};
		
		return $api{$key};
	}
}

=back

=head1 AUTHOR

Sascha Kiefer, L<esskar@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 Sascha Kiefer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;