require 'mcrypt.so'

class Mcrypt

  private
  
  # if key and iv are passed to new(), they will be passed through
  # here for processing
  def after_init(key=nil,iv=nil) #:nodoc:
  end

end
