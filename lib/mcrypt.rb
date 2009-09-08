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

    # Provides information about the specified algorithm.
    # Returns a hash with the following keys:
    # [:block_algorithm]  true if the algorithm operates in blocks (mutually exclusive with stream_algorithm)
    # [:stream_algorithm] true if the algorithm operates in bytes (mutually exclusive with block_algorithm)
    # [:block_size]       the size of blocks the algorithm works with (in bytes)
    # [:key_size]         the maximum key size this algorithm will accept (in bytes)
    # [:key_sizes]        an array containing all the key sizes the algorithm will accept (in bytes)
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

    # Returns true if the algorithm specified operates in bytes.
    # This is mutually exclusive with <tt>block_algorithm?</tt>.
    def stream_algorithm?(algorithm_name)
      ! block_algorithm?(algorithm_name)
    end

    # Provides information about the specified operation mode.
    # Returns a hash with the following keys:
    # [:block_mode]            true if the mode operates in blocks (mutually exclusive with stream_mode)
    # [:stream_mode]           true if the mode operates in bytes (mutually exclusive with block_mode)
    # [:block_algorithm_mode]  true if the mode is for use with block algorithms (mutually exclusive with stream_algorithm_mode)
    # [:stream_algorithm_mode] true if the mode is for use with stream algorithms (mutually exclusive with block_algorithm_mode)
    # [:mode_version]          an integer identifying the version of the mode implementation
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

    # Returns true if the mode specified operates in bytes.
    # This is mutually exclusive with <tt>block_mode?</tt>.
    def stream_mode?(mode_name)
      ! block_mode?(mode_name)
    end

    # Returns true if the mode specified is for use with stream algorithms (e.g. ARCFOUR)
    # This is mutually exclusive with <tt>block_algorithm_mode?</tt>.
    def stream_algorithm_mode?(mode_name)
      ! block_algorithm_mode?(mode_name)
    end

    # Converts :rijndael_256 to "rijndael-256".
    # No need to call manually -- it's called for you when needed.
    def canonicalize_algorithm(algo) #:nodoc:
      algo.to_s.downcase.gsub(/_/,'-')
    end
  end

  # The canonical name of the algorithm currently in use.
  attr_reader :algorithm

  # The name of the mode currently in use.
  attr_reader :mode

  # The key currently in use (raw binary).
  attr_reader :key

  # The IV currently in use (raw binary).
  attr_reader :iv

  # One of +false+ (default), <tt>:pkcs</tt> or <tt>:zeros</tt>.  See <tt>padding=</tt> for details.
  attr_reader :padding

  # Set the cryptographic key to be used. This is the <em>final raw
  # binary representation</em> of the key (i.e. not base64 or hex-encoded).
  #
  # The key is validated to ensure it is an acceptable length for the
  # algorithm currently in use (specified in call to +new+).
  #
  # The key cannot be reassigned while the object is mid-encryption/decryption
  # (e.g. after encrypt_more but before encrypt_finish).
  # Attempting to do so will raise an exception.
  def key=(new_key)
    if @opened
      raise(RuntimeError, "cannot change key mid-stream")
    end
    @key = validate_key(new_key)
  end

  # Set the initialization vector (IV) to be used. This is the <em>final
  # raw binary representation</em> of the key (i.e. not base64 or hex-encoded).
  #
  # The IV cannot be reassigned while the object is mid-encryption/decryption
  # (e.g. after encrypt_more but before encrypt_finish).
  # Attempting to do so will raise an exception.
  #
  # If the mode in use does not use an IV and +new_iv+ is non-nil,
  # an exception will be raised to prevent you shooting yourself in
  # the foot.
  def iv=(new_iv)
    if @opened
      raise(RuntimeError, "cannot change IV mid-stream")
    end
    @iv = validate_iv(new_iv)
  end

  # Set the padding technique to be used. Most ciphers work in
  # blocks, not bytes, so unless you know that the size of your
  # plaintext will always be a multiple of the cipher's block size,
  # you'll need to use some sort of padding.
  #
  # <tt>padding_type.to_s</tt> should be one of:
  #
  # ["pkcs","pkcs5","pkcs7"]
  #   Use pkcs5/7 padding which is safe for use with arbitrary binary
  #   inputs (as opposed to null-terminated C-strings). Each byte of
  #   padding contains the number of bytes of padding used. For example,
  #   if 5 bytes of padding are needed, each byte has the value 0x05. See
  #   {RFC 2315}[http://tools.ietf.org/html/rfc2315#page-22] for a more
  #   detailed explanation. Padding is <em>always</em> added to
  #   disambiguate an incomplete message from one that happens to fall on
  #   block boundaries.
  #
  # ["zeros"]
  #   Pads the plaintext with NUL characters. This works fine with C-
  #   strings. Don't use it with anything that might have other embedded
  #   nulls.
  #
  # ["none"]
  #   No padding is used. Will throw exceptions if the input size does
  #   not fall on block boundaries.
  #
  # You can also pass +true+ (which means "pkcs") or +false+ (no
  # padding). No padding is used by default.
  #
  # N.B. This is not a feature of libmcrypt but of this Ruby module.
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

  # Returns true if the mode in use operates in bytes.
  def stream_mode?
    ! block_mode?
  end

  # Encrypts +plaintext+ and returns the encrypted result in one step.
  # Use this for small inputs.
  #
  # To save memory when encrypting larger inputs, process the plaintext
  # in chunks instead by using +encrypt_more+ and +encrypt_finish+.
  def encrypt(plaintext)
    if @opened
      raise(RuntimeError, "cannot combine streaming use and atomic use")
    end
    encrypt_more(plaintext) << encrypt_finish
  end

  # Encrypts +plaintext+ and returns a chunk of ciphertext. Input to
  # this function is buffered across calls until it is large enough to
  # fill a complete block (as defined by the algorithm in use), at which
  # point the encrypted data will be returned. If there is not enough
  # buffer to encrypt an entire block, an empty string will be returned.
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

  # Completes the encryption process and returns the final ciphertext chunk if
  # any.
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

  # Decrypts +ciphertext+ and returns the decrypted result in one step.
  # Use this for small inputs.
  #
  # To save memory when decrypting larger inputs, process the ciphertext
  # in chunks instead by using +decrypt_more+ and +decrypt_finish+.
  def decrypt(ciphertext)
    if @opened
      raise(RuntimeError, "cannot combine streaming use and atomic use")
    end
    decrypt_more(ciphertext) << decrypt_finish
  end

  # Decrypts +ciphertext+ and returns a chunk of plaintext. Input to
  # this function is buffered across calls until it is large enough to
  # safely perform the decryption (as defined by the block size of
  # algorithm in use). When there is enough data, a chunk of the
  # decrypted data is returned. Otherwise it returns an empty string.
  # 
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

  # Completes the decryption process and returns the final plaintext chunk.
  def decrypt_finish
    open_td

    # no buffering/padding in stream mode
    return '' if stream_mode?

    # There should always be exactly zero or one block(s) in the buffer
    # at this point, because the input should be on block boundaries,
    # and we've consumed all available blocks but one in decrypt_more().
    if ! [0,block_size].include?(buffer.length)
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
    @buffer
  end

  # This gets called by +initialize+ which is implemented in C.
  # If key and iv are passed to new(), they will be passed through
  # here for processing.
  def after_init(key=nil,iv=nil) #:nodoc:
    @padding = false
    @buffer  = ""

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
    if iv.nil? && !has_iv?
      nil
    elsif !has_iv?
      raise(InvalidIVError, "Mode #{mode} does not use an IV.")
    elsif iv.length == iv_size
      iv
    else
      raise(InvalidIVError, "IV length #{iv.length} is not supported by #{mode}.")
    end
  end

  def validate!
    validate_key(@key)
    if has_iv?
      if @iv.nil?
        raise(InvalidIVError, "#{algorithm}/#{mode} requires an IV but none was provided.")
      end
      validate_iv(@iv)
    end
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
    else
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
