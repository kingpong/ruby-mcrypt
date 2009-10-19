#!/usr/bin/env ruby
require 'mkmf'
extension_name = 'mcrypt'
dir_config(extension_name)
unless have_header("mcrypt.h") && have_library("mcrypt","mcrypt_module_open")
  $stderr.puts <<-EOF

########################################################################

Unable to find your mcrypt library.

Make sure you have libmcrypt installed (and libmcrypt-devel if you're
on a Linux distribution that does things that way).

If your libmcrypt is in a nonstandard location and has header files in
PREFIX/include and libraries in PREFIX/lib, try installing the gem like
this (note the extra "--"):

  gem install kingpong-ruby-mcrypt --source=http://gems.github.com \\
      -- --with-mcrypt-dir=/path/to/mcrypt/prefix

You can also specify the include and library directories separately:

  gem install kingpong-ruby-mcrypt --source=http://gems.github.com \\
      -- --with-mcrypt-include=/path/to/mcrypt/include \\
         --with-mcrypt-lib=/path/to/mcrypt/lib

########################################################################

  EOF
  exit 1
end
create_makefile(extension_name)
