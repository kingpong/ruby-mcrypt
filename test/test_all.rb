#!/usr/bin/env ruby

HERE = File.dirname(__FILE__)
require File.join(HERE, "helper.rb")

require 'mcrypt'

class McryptTest < Test::Unit::TestCase
  
  def setup
    @key = "0123456789012345".freeze
    @iv  = "0123456789012345".freeze
  end

  def test_instantiate
    mc = Mcrypt.new(:tripledes, :cbc, @key.dup, @iv.dup)
    assert_not_nil mc
  end

end
