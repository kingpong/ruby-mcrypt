
$VERBOSE = false
require 'test/unit'

begin
  here = File.dirname(__FILE__)
  %w(lib bin test).each do |dir|
    path = "#{here}/../#{dir}"
    $LOAD_PATH.unshift(path) unless $LOAD_PATH.include?(path)
  end
end

