# passwordcheck_with_params

The PostgeSQL module [passwordcheck](https://www.postgresql.org/docs/current/passwordcheck.html) is simple module, where all rules are hardcoded and parameters cannot be used.

This module, called passwordcheck_with_params is an extended version, which allows parametrization. It handles lowercase, uppercase, numeric and special characters separately. Characters can also be disallowed.
It also gives the user a possibility to use cracklib, including a dictionary. (Note that cracklib cannot be parametrized either. This implementation, however, could be extended further to only take into consideration certain cracklib rules...)

To see the list of parameters, you may run: select name, min_val, max_val, short_desc from pg_settings where name like 'passwordcheck%';

This implementation provides a single, global password profile.

## Compilation and installation
### Compile the module
Install these packages:
- postgresql14-devel 
- gcc 
- git 
- cracklib-devel (optional)

Package names might differ depending on the distribution. (For CentOS, you will also need EPEL, centos-release-scl and llvm-toolset-7.)


    su - postgres

    git clone -b REL_14_STABLE --single-branch git://git.postgresql.org/git/postgresql.git

    mkdir postgresql/contrib/passwordcheck_with_params

    cd postgresql/contrib/passwordcheck_with_params 

    wget https://github.com/rblst/rblst/blob/main/postgresql/passwordcheck/passwordcheck_with_params.c

    cp ../passwordcheck/Makefile . 
    sed -i 's/passwordcheck/passwordcheck_with_params/g' Makefile # rename the module
    sed -i "s|/usr/lib/cracklib_dict|$HOME/cracklib_dict/en_hu|" Makefile # set custom cracklib dict location (optional)
    sed -i -e 's/^# \(PG_CPPFLAGS.*\)/\1/' -e 's/^# \(SHLIB_LINK.*\)/\1/' Makefile # enable cracklib (optional)

    make
### Install the module
As root:

    cp /var/lib/pgsql/passwordcheck/postgresql/contrib/passwordcheck_with_params/passwordcheck_with_params.so $(pg_config --libdir)

### Load the module


In postgresql.conf:

    shared_preload_libraries = 'passwordcheck_with_params'

### Create cracklib dictionary (optional)
Install the words package.

    su - postgres

    mkdir $HOME/cracklib_dict
    cd $HOME/cracklib_dict

    cat /usr/share/dict/words pwdict_hun.txt > en_hu # Hungarian dictionary optional

    gzip en_hu
    cracklib-format en_hu | cracklib-packer $HOME/cracklib_dict/en_hu
