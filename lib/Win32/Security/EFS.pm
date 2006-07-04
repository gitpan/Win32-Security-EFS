package Win32::Security::EFS;

use strict;
use warnings;
use base qw/Exporter DynaLoader/;

use constant {
    FILE_ENCRYPTABLE        => 0,
    FILE_IS_ENCRYPTED       => 1,
    FILE_SYSTEM_ATTR        => 2,
    FILE_ROOT_DIR           => 3,
    FILE_SYSTEM_DIR         => 4,
    FILE_UNKNOWN            => 5,
    FILE_SYSTEM_NOT_SUPPORT => 6,
    FILE_USER_DISALLOWED    => 7,
    FILE_READ_ONLY          => 8,
    FILE_DIR_DISALLOWED     => 9,
};

my @constant_names = qw/
  FILE_ENCRYPTABLE
  FILE_IS_ENCRYPTED
  FILE_SYSTEM_ATTR
  FILE_ROOT_DIR
  FILE_SYSTEM_DIR
  FILE_UNKNOWN
  FILE_SYSTEM_NOT_SUPPORT
  FILE_USER_DISALLOWED
  FILE_READ_ONLY
  FILE_DIR_DISALLOWED
  /;

my %function_definitions = (
    EncryptFile          => [ 'advapi32', 'P',  'I' ],
    DecryptFile          => [ 'advapi32', 'PN', 'I' ],
    FileEncryptionStatus => [ 'advapi32', 'PP', 'I' ],
);

my @xs_function_names = qw/
  QueryUsersOnEncryptedFile
  /;

use vars qw/$VERSION @EXPORT_OK %EXPORT_TAGS/;
$VERSION     = '0.08';
@EXPORT_OK   = @constant_names, keys %function_definitions, @xs_function_names;
%EXPORT_TAGS =
  ( consts => [@constant_names], api => [ keys %function_definitions, @xs_function_names ] );

require XSLoader;
XSLoader::load('Win32::Security::EFS', $VERSION);

use Win32::API ();
use File::Spec ();

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

    my ( undef, $flags, undef ) = Win32::FsType();
    return ( $flags & 0x00020000 ) > 0;
}

=item B<encrypt($filename)>

The I<encrypt> function encrypts a file or directory. All data streams in a file are encrypted.
All new files created in an encrypted directory are encrypted.

=cut

sub encrypt {
    my ( $self, $filename ) = @_;
    return EncryptFile($filename);
}

=item B<decrypt($filename)>

The I<decrypt> function decrypts an encrypted file or directory.

=cut

sub decrypt {
    my ( $self, $filename ) = @_;
    return DecryptFile( $filename, 0 );
}

=item B<encryption_status($filename)>

The I<encryption_status> function retrieves the encryption status of the specified file.

If the function succeeds, it will return one of the following values see the L</CONSTANTS> section.

=cut

sub encryption_status {
    my ( $self, $filename ) = @_;
    my $result = FileEncryptionStatus( $filename, my $status );
    return $result ? unpack( "L*", $status ) : undef;
}

{
    my %api = ();

    sub import_api {
        my $func = shift;
        my $def  = $function_definitions{$func}
          or die "No definition found for API $func!";
        my $key = join "_",
          map { uc } ( $def->[0], $func, $def->[1], $def->[2] );

        my $retval;
        $retval = $api{$key} =
          Win32::API->new( $def->[0], $func, $def->[1], $def->[2] )
          unless exists $api{$key};

        die "Could not import API $func: $!" unless defined $retval;

        return $retval;
    }
}

=back

=head2 FUNCTIONS

You have the possibility to access the plain API directly. Therefore the
following functions can be exported:

    use Win32::Security::EFS ':api';



=over 4

=item B<EncryptFile($filename)>

    BOOL EncryptFile(
        LPCTSTR lpFileName  // file name
    );


=cut

sub EncryptFile {
    my ($filename) = @_;
    my $func = import_api('EncryptFile');
    return $func->Call( File::Spec->canonpath($filename) );
}

=item B<DecryptFile($filename, $reserved)>

    BOOL DecryptFile(
        LPCTSTR lpFileName,  // file name
        DWORD dwReserved     // reserved; must be zero
    );


=cut

sub DecryptFile {
    my ( $filename, $reserved ) = @_;
    my $func = import_api('DecryptFile');
    return $func->Call( File::Spec->canonpath($filename), $reserved );
}

=item B<FileEncryptionStatus($filename, $status)>

    BOOL FileEncryptionStatus(
        LPCTSTR lpFileName,  // file name
        LPDWORD lpStatus     // encryption status
    );


=cut

sub FileEncryptionStatus {
    my ( $filename, $status ) = @_;

    $status = "\0" x 4;    # 4 == sizeof(DWORD)
    my $func = import_api('FileEncryptionStatus');
    return $func->Call( File::Spec->canonpath($filename), $status );
}

=back

=head1 CONSTANTS

=over 4

You can import all constants by importing Win32::Security::EFS like

	use Win32::Security::EFS ':consts';




=item *
encryption_status constants

=over 4

=item *
I<FILE_DIR_DISALLOWED:>
Reserved for future use.

=item *
I<FILE_ENCRYPTABLE:>
The file can be encrypted.

=item *
I<FILE_IS_ENCRYPTED:>
The file is encrypted.

=item *
I<FILE_READ_ONLY:>
The file is a read-only file.

=item *
I<FILE_ROOT_DIR:>
The file is a root directory. Root directories cannot be encrypted.

=item *
I<FILE_SYSTEM_ATTR:>
The file is a system file. System files cannot be encrypted.

=item *
I<FILE_SYSTEM_DIR:>
The file is a system directory. System directories cannot be encrypted.

=item *
I<FILE_SYSTEM_NOT_SUPPORT:>
The file system does not support file encryption.

=item *
I<FILE_UNKNOWN:>
The encryption status is unknown. The file may be encrypted.

=item *
I<FILE_USER_DISALLOWED:>
Reserved for future use.

=back

=back

=head1 AUTHOR

Sascha Kiefer, L<esskar@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 Sascha Kiefer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
