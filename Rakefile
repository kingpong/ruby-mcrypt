require 'rubygems'
require 'rbconfig'
require 'rake'
require 'rake/testtask'

# http://stackoverflow.com/questions/213368/how-can-i-reliably-discover-the-full-path-of-the-ruby-executable
RUBY = File.join(RbConfig::CONFIG['bindir'], RbConfig::CONFIG['ruby_install_name']).sub(/.*\s.*/m, '"\&"')

ENV["MAINTAINER_MODE"] = "1" if File.exists?(File.dirname(__FILE__) + "/MAINTAINER")

task :default => :test

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "ruby-mcrypt"
    gemspec.summary = "Ruby bindings for libmcrypt"
    gemspec.description = File.read(File.join(File.dirname(__FILE__),"README.rdoc"))
    gemspec.email = "philgarr@gmail.com"
    gemspec.homepage = "http://github.com/kingpong/ruby-mcrypt"
    gemspec.authors = ["Philip Garrett"]
    gemspec.required_ruby_version = '>= 1.8.6'
    gemspec.requirements << 'libmcrypt (2.5.x or 2.6.x, tested with 2.5.8)'
  end 
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler not available. Install it with: gem install jeweler"
end

EXTENSION = "ext/mcrypt.#{RbConfig::CONFIG["DLEXT"]}"

desc "Compile extension"
task :compile => EXTENSION
file EXTENSION => FileList["ext/Makefile","ext/*.c"] do
  Dir.chdir("ext") do
    opts = ENV["MAINTAINER_MODE"] ? ["V=1"] : []
    system("make", *opts) || raise("could not build ruby-mcrypt")
  end
end

file "ext/Makefile" => ["ext/extconf.rb"] do
  Dir.chdir("ext") do
    system("RUBY","extconf.rb",*ARGV) || raise("could not configure ruby-mcrypt for your system")
  end
end

desc "Delete build files and products"
task :clean do
  %W( #{EXTENSION} ext/Makefile ext/*.o ).each do |pattern|
    Dir[pattern].each {|filespec| File.unlink(filespec) }
  end
end

Rake::TestTask.new do |t|
  t.libs << ["test", "ext"]
  t.test_files = FileList['test/test*.rb']
  t.verbose = true
end
task :test => FileList[EXTENSION, "lib/mcrypt.rb"]







