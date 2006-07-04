use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl	=> 'traditional',
    license		=> 'perl',
    module_name		=> 'Win32::Security::EFS',
    requires		=> {
        'Win32'			=> 0.24,
        'Win32::API'	=> 0.41,
        'File::Spec'	=> 3.05,
    },
    reccomends => {
    },
    create_readme => 1,
    sign          => 0,
);
$build->create_build_script;