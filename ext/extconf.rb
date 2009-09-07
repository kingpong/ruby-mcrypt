#!/usr/bin/env ruby
require 'mkmf'
extension_name = 'mcrypt'
dir_config(extension_name)

inc_dirs = ['/opt/local/include']
unless have_header("mcrypt.h") || find_header("mcrypt.h",inc_dirs)
  $stdout.print "Enter your libmcrypt includes dir: "
  $stdout.flush
  inc_dirs << $stdin.gets.chomp
end
find_header("mcrypt.h",inc_dirs)

lib_dirs = ['/opt/local/lib']
unless have_library("mcrypt","mcrypt_module_open","mcrypt.h") || find_library("mcrypt","mcrypt_module_open",*lib_dirs)
  $stdout.print "Enter your libmcrypt lib dir: "
  $stdout.flush
  lib_dirs << $stdin.gets.chomp
end
find_library("mcrypt","mcrypt_module_open",*lib_dirs)

create_makefile(extension_name)
