#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__),"helper.rb")

class McryptReciprocityTest < Test::Unit::TestCase

  def generate(len)
    "0" * len
  end

  def make_mcrypt(algo,mode,padding)
    mc = Mcrypt.new(algo,mode)
    mc.key = generate(mc.key_size)
    mc.iv = generate(mc.iv_size) if mc.has_iv?
    mc.padding = padding
    mc
  end

  # test a few algorithms
  # with both stream and block modes,
  # with different padding implementations
  # with different input sizes
  # with on-boundary and off-boundary

  [:tripledes,:twofish,:rijndael_256].each do |algorithm|
    [:cbc, :cfb, :ecb].each do |mode|
      [:zeros,:pkcs,:none].each do |padding_type|
        [1,2,3].each do |blocks|

          define_method("test_#{algorithm}_#{mode}_#{padding_type}_#{blocks}_on_boundary") do
            mc = make_mcrypt(algorithm,mode,padding_type)
            plaintext = generate(mc.block_size * blocks)
            assert_equal plaintext, mc.decrypt(mc.encrypt(plaintext))
          end

          # off-boundary only works without padding for stream modes
          if padding_type != :none || Mcrypt.stream_mode?(mode)
            define_method("test_#{algorithm}_#{mode}_#{padding_type}_#{blocks}_off_boundary") do
              mc = make_mcrypt(algorithm,mode,padding_type)
              plaintext = generate((mc.block_size * blocks) - 1)
              assert_equal plaintext, mc.decrypt(mc.encrypt(plaintext))
            end
          end

        end
      end
    end
  end
  
end
