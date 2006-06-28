use Test::More tests => 4;

use_ok('Win32::Security::EFS');

SKIP: {
    skip "EFS not supported by your file system.", 3
      unless Win32::Security::EFS->supported();

    ok(Win32::Security::EFS::supported);
    
    my $testfile = 'test_win32_security_efs.tmp';
    open(TMP, "> $testfile");
    print TMP "Test";
    close TMP;
    
    ok(Win32::Security::EFS->encrypt($testfile), 'encrypt test');
    ok(Win32::Security::EFS->decrypt($testfile), 'decrypt test');
    
    unlink $testfile;
}