#!/usr/bin/env ruby

HERE = File.dirname(__FILE__)
require File.join(HERE, "helper.rb")

require 'mcrypt'

class McryptTest < Test::Unit::TestCase
  
  def setup
    @key = "0123456789012345".freeze
    @iv  = "0123456789012345".freeze
  end

  def test_instantiate_basic
    mc = Mcrypt.new(:tripledes, :cbc)
    assert_not_nil mc
  end

  def test_invalid_algorithm_or_mode
    # blatantly incorrect algorithm
    assert_raise Mcrypt::InvalidAlgorithmOrModeError do
        Mcrypt.new(:no_such_algorithm, :cbc)
    end
    # blatantly incorrect mode
    assert_raise Mcrypt::InvalidAlgorithmOrModeError do
        Mcrypt.new(:tripledes, :no_such_mode)
    end
    # bad combination of otherwise valid algo/mode
    assert_raise Mcrypt::InvalidAlgorithmOrModeError do
        Mcrypt.new(:wake, :cbc)
    end
  end

  def test_is_block_algorithm
    assert_equal Mcrypt.new(:tripledes, :cbc).is_block_algorithm, true
    assert_equal Mcrypt.new(:wake, :stream).is_block_algorithm, false
  end
  
  def test_key_size
    assert_equal Mcrypt.new(:tripledes, :cbc).key_size, 24
  end

end
