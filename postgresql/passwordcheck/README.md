# passwordcheck_with_params

The `passwordcheck_with_params` module provides a single, global password profile for PostgreSQL.

It is built on the supplied [passwordcheck](https://www.postgresql.org/docs/current/passwordcheck.html) module, which only offers hard-coded rules, without any parameters.

This module is called `passwordcheck_with_params` because it allows some parametrization. It handles certain character classes (lowercase, uppercase, numeric and special characters) separately. You can also disallow certain characters.

To see the list of parameters for this module, you may run: 

    SELECT name, min_val, max_val, short_desc FROM pg_settings WHERE name LIKE 'passwordcheck%';

Just as the passwordcheck module, passwordcheck_with_params also allows you to use cracklib, including checking passwords against a dictionary. Note, however, that if you use cracklib, then cracklib's built-in rules will be enforced, regardless of the parameter values set for the module.
Unfortunately, cracklib itself cannot be parametrized either. This implementation, however, could be extended further to only take into consideration certain cracklib rules...

## Compilation, installation and loading
This description is for PostgreSQL 14, but it should work similarly for different versions.

### Compile the module

#### Install packages

- `postgresql14-devel` 
- `gcc` 
- `git` 
- `cracklib-devel` (optional, for cracklib support)

Package names might differ depending on the distribution. (For CentOS, you may also need the EPEL repository as well as the `centos-release-scl` and `llvm-toolset-7`packages.)

#### Switch to postgres user
    su - postgres

#### Download PostgreSQL source
    git clone -b REL_14_STABLE --single-branch git://git.postgresql.org/git/postgresql.git

#### Create directory for the module 
Create a directory inside the downloaded source directory and change to it

    mkdir postgresql/contrib/passwordcheck_with_params
    cd postgresql/contrib/passwordcheck_with_params 

#### Download passwordcheck_with_param source
    wget https://raw.githubusercontent.com/rblst/rblst/main/postgresql/passwordcheck/passwordcheck_with_params.c

#### Create Makefile
You can  simply copy the Makefile in the passwordcheck module

    cp ../passwordcheck/Makefile . 
    
and modify it:

    sed -i 's/passwordcheck/passwordcheck_with_params/g' Makefile  # rename the module
    sed -i "s|/usr/lib/cracklib_dict|$HOME/cracklib_dict/en_hu|" Makefile  # set custom cracklib dict location (optional)
    sed -i -e 's/^# \(PG_CPPFLAGS.*\)/\1/' -e 's/^# \(SHLIB_LINK.*\)/\1/' Makefile  # enable cracklib (optional)

If you enable cracklib, then you need to have installed the cracklib development package.

#### Compile the module
    make
    
### Install the module
You need to run the installation step as root.
Make sure that `pg_config` is on path.

    cp /var/lib/pgsql/passwordcheck/postgresql/contrib/passwordcheck_with_params/passwordcheck_with_params.so $(pg_config --libdir)


### Load the module

Set the following parameter in `postgresql.conf`:

    shared_preload_libraries = 'passwordcheck_with_params'

You must restart the server for the module to be used.

## Creating a cracklib dictionary (optional)
### Install packages
Install the following packages
- `cracklib` ??? password checker library + utilities to manage dictionaries
- `words` ??? a dictionary of English words (there are many more out there: https://github.com/cracklib/cracklib/tree/master/words)

### Create dictionary

#### Switch to postgres user

    su - postgres
   
#### Create directory for dictionary files
Make sure the directory path is the same as in the `Makefile` created above.

    mkdir $HOME/cracklib_dict
    cd $HOME/cracklib_dict

#### Add Hungarian word list (optional)

##### Download Hungarian word list
You can use any word list. The file must contain one word per line.


    wget https://raw.githubusercontent.com/Blkzer0/Wordlists/master/Hungarian.txt
    
##### Concatenate English and Hungarian word lists
Make sure that the dictionary file name is the same as in the `Makefile` created above.

    cat /usr/share/dict/words Hungarian.txt > en_hu

#### Gzip the word list
This step is needed for generating dictionary files.

    gzip en_hu
    
#### Generate dictionary files
The `cracklib-format` utility lowercases all words, removes control characters, and sorts the lists.

The `cracklib-packer` utility takes the sorted and cleaned list, and creates a database in the directory and with the prefix given by the argument. It generates three file with the suffixes of `.hwm`, `.pwd`, and `.pwi`.

    cracklib-format en_hu | cracklib-packer $HOME/cracklib_dict/en_hu
