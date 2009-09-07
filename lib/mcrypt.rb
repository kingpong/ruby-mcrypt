require 'mcrypt.so'

class Mcrypt

  class << self

    # Converts :rijndael_256 to "rijndael-256".
    # No need to call manually -- it's called for you when needed.
    def canonicalize_algorithm(algo) #:nodoc:
      algo.to_s.gsub(/_/,'-')
    end
  end

  # these are populated in C.
  attr_reader :algorithm, :mode

  private
  
  # if key and iv are passed to new(), they will be passed through
  # here for processing
  def after_init(key=nil,iv=nil) #:nodoc:
  end

end
