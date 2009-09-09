# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ruby-mcrypt}
  s.version = "0.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = ["Philip Garrett"]
  s.date = %q{2009-09-09}
  s.description = %q{Ruby bindings for libmcrypt}
  s.email = %q{philip@pastemagazine.com}
  s.extensions = ["ext/extconf.rb"]
  s.extra_rdoc_files = ["README.rdoc", "ext/extconf.rb", "ext/mcrypt_wrapper.c", "lib/mcrypt.rb"]
  s.files = ["Manifest", "README.rdoc", "Rakefile", "ext/extconf.rb", "ext/mcrypt_wrapper.c", "lib/mcrypt.rb", "mcrypt.gemspec", "test/generate/Makefile", "test/generate/generate_testcases.c", "test/helper.rb", "test/test_all.rb", "test/test_basics.rb", "test/test_brute.rb", "test/test_reciprocity.rb", "ruby-mcrypt.gemspec"]
  s.homepage = %q{http://github.com/kingpong/ruby-mcrypt}
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Ruby-mcrypt", "--main", "README.rdoc"]
  s.require_paths = ["lib", "ext"]
  s.rubyforge_project = %q{ruby-mcrypt}
  s.rubygems_version = %q{1.3.3}
  s.summary = %q{ruby-mcrypt 0.0.1}
  s.test_files = ["test/test_all.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
