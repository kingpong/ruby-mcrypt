require 'mcrypt.so'

class Mcrypt

  # these are populated in C.
  attr_reader :algorithm, :mode

  private
  
  # if key and iv are passed to new(), they will be passed through
  # here for processing
  def after_init(key=nil,iv=nil) #:nodoc:
  end

  # converts :rijndael_256 to "rijndael-256"
  def canonicalize_algorithm(algo) #:nodoc:
    algo.to_s.gsub(/_/,'-')
  end

end
