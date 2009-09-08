#
# mcrypt.rb
#
# Copyright (c) 2009 Philip Garrett.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
require 'mcrypt.so'

# maybe later:
# td = Mcrypt.new(:rijndael_256, :cfb, key, iv, :padding => true)
# td.open(File.open("foo")) do |stream|
#   print stream.read
# end

class Mcrypt

  class InvalidKeyError < ArgumentError; end
  class InvalidIVError < ArgumentError; end
  class PaddingError < RuntimeError; end

  class << self

    # Returns a hash with the following keys:
    #
    # +:block_algorithm+: true if the algorithm is a block algorithm
    #
    # +:stream_algorithm+: true if the algorithm is a stream algorithm (i.e. !block_algorithm)
    #
    # +:block_size+: the size of blocks the algorithm works with (in bytes)
    #
    # +:key_size+: the maximum key size this algorithm will accept (in bytes)
    #
    # +:key_sizes+: an array containing all the key sizes the algorithm will accept (in bytes)
    #
    def algorithm_info(algorithm_name)
      {
        :block_algorithm   => block_algorithm?(algorithm_name),
        :stream_algorithm  => stream_algorithm?(algorithm_name),
        :block_size        => block_size(algorithm_name),
        :key_size          => key_size(algorithm_name),
        :key_sizes         => key_sizes(algorithm_name),
        :algorithm_version => algorithm_version(algorithm_name)
      }
    end

    def stream_algorithm?(algorithm_name)
      ! block_algorithm?(algorithm_name)
    end

    # Returns a hash with the following keys:
    #
    # +:block_mode+: true if the mode is a block mode
    #
    # +:stream_mode+: true if the mode is a stream mode
    #
    # +:block_algorithm_mode+: true if the mode is for use with block algorithms
    #
    # +:stream_algorithm_mode+: true if the mode is for use with stream algorithms
    #
    # +:mode_version+: an integer identifying the version of the mode implementation
    #
    def mode_info(mode_name)
      {
        :block_mode            => block_mode?(mode_name),
        :stream_mode           => stream_mode?(mode_name),
        :block_algorithm_mode  => block_algorithm_mode?(mode_name),
        :stream_algorithm_mode => stream_algorithm_mode?(mode_name),
        :mode_version          => mode_version(mode_name)
      }
    end

    def stream_mode?(mode_name)
      ! block_mode?(mode_name)
    end

    def stream_algorithm_mode?(mode_name)
      ! block_algorithm_mode?(mode_name)
    end

    # Converts :rijndael_256 to "rijndael-256".
    # No need to call manually -- it's called for you when needed.
    def canonicalize_algorithm(algo) #:nodoc:
      algo.to_s.gsub(/_/,'-')
    end
  end

  attr_reader :algorithm, :mode
  attr_reader :key, :iv, :padding

  def key=(new_key)
    if @opened
      raise(RuntimeError, "cannot change key mid-stream")
    end
    @key = validate_key(new_key)
  end

  def iv=(new_iv)
    if @opened
      raise(RuntimeError, "cannot change IV mid-stream")
    end
    @iv = validate_iv(new_iv)
  end

  def padding=(padding_type)
    @padding = case padding_type.to_s
      when "true", /\Apkcs/
        @padding = :pkcs
      when /\Azero/
        @padding = :zeros
      when "false", "none", ""
        @padding = false
      else
        raise(ArgumentError, "invalid padding type #{padding_type.to_s}")
      end
  end

  def stream_mode?
    ! block_mode?
  end

  def encrypt(plaintext)
    if @opened
      raise(RuntimeError, "cannot combine streaming use and atomic use")
    end
    encrypt_more(plaintext) << encrypt_finish
  end

  def encrypt_more(plaintext)
    open_td

    return encrypt_generic(plaintext) if stream_mode?

    # buffer plaintext and process in blocks.
    # stream modes return 1 for block_size so this still works.
    buffer << plaintext
    blocks = buffer.length / block_size

    if blocks == 0
      # we don't have an entire block yet.  keep buffering
      ''
    else
      encrypt_generic(buffer.slice!(0,blocks*block_size))
    end
  end

  def encrypt_finish
    open_td

    # no buffering/padding in stream mode
    return '' if stream_mode?

    # nothing to encrypt, no padding to add
    return '' if buffer.length == 0 && !padding

    buffer << padding_str
    ciphertext = encrypt_more('') # consume existing buffer

    if buffer.length > 0
      raise(RuntimeError, "internal error: buffer should be empty")
    end

    ciphertext
  ensure
    close_td
  end

  def decrypt(ciphertext)
    if @opened
      raise(RuntimeError, "cannot combine streaming use and atomic use")
    end
    decrypt_more(ciphertext) << decrypt_finish
  end

  def decrypt_more(ciphertext)
    open_td

    # no buffering in stream mode
    return decrypt_generic(ciphertext) if stream_mode?

    # buffer ciphertext and process in blocks.
    buffer << ciphertext
    blocks = buffer.length / block_size

    if blocks > 1
      # maintain at least one block of buffer, because it may be padding
      # that we'll need to process in decrypt_finish.
      decrypt_generic(buffer.slice!(0,(blocks - 1)*block_size))
    else
      # we don't have enough blocks yet. keep buffering
      ''
    end
  end

  def decrypt_finish
    open_td

    # no buffering/padding in stream mode
    return '' if stream_mode?

    # There should always be exactly one block in the buffer at this
    # point, because the input should be on block boundaries.
    if buffer.length != block_size
      raise(RuntimeError, "input is not a multiple of the block size (#{block_size})")
    end

    plaintext = decrypt_generic(buffer.slice!(0,buffer.length))

    case padding
    when :pkcs
      unpad_pkcs(plaintext)
    when :zeros
      plaintext.sub!(/\0*\Z/,'')
    else
      plaintext
    end
  ensure
    close_td
  end
  
  # todo: figure out how to declare these private in the extension file
  private :generic_init, :encrypt_generic, :decrypt_generic

  private

  def buffer
    @buffer ||= ""
  end

  # If key and iv are passed to new(), they will be passed through
  # here for processing
  def after_init(key=nil,iv=nil) #:nodoc:
    self.key = key if key
    self.iv  = iv  if iv
  end

  def validate_key(key)
    if key.length == key_size || key_sizes.include?(key.length)
      key
    else
      raise(InvalidKeyError, "Key length #{key.length} is not supported by #{algorithm}.")
    end
  end

  def validate_iv(iv)
    unless has_iv?
      raise(InvalidIVError, "Mode #{mode} does not use an IV.")
    end
    if iv.length == iv_size
      iv
    else
      raise(InvalidIVError, "IV length #{iv.length} is not supported by #{mode}.")
    end
  end

  def validate!
    validate_key(@key)
    validate_iv(@iv) if has_iv?
  end

  def open_td
    return if @opened
    validate!
    generic_init
    @opened = true
  end

  def close_td
    return unless @opened
    generic_deinit
    @opened = false
  end

  def padding_str
    if buffer.length > block_size
      raise(RuntimeError, "internal error: buffer is larger than block size")
    end

    pad_size = block_size - buffer.length
    pad_size = block_size if pad_size == 0  # add a block to disambiguate
    pad_char = nil
    case padding
    when :pkcs
      pad_char = "%c" % pad_size
    when :zeros
      pad_char = "%c" % 0
    when false
      raise(RuntimeError, "Input is not an even multiple of the block size " +
            "(#{block_size}), but no padding has been specified.")
    end
    pad_char * pad_size
  end

  def unpad_pkcs(block)
    chars = block.unpack('C*')
    padding_bytes = mod = chars.last
    if mod > chars.length
      raise(PaddingError, "incorrect pkcs padding mod value #{mod}")
    end
    while padding_bytes > 0
      if chars.last != mod
        raise(PaddingError, "incorrect pkcs padding character #{chars.last} (should be #{mod})")
      end
      chars.pop
      padding_bytes -= 1
    end
    chars.pack('C*')
  end

end
