# frozen_string_literal: true

module Gost3410Algorithm
class Converter
  def self.bignumToBytes(bn, size)
    s = bn.to_s(16)
    s = ('0' * (size * 2 - s.length)) + s
    sa = s.scan(/../)
    ba = []
    sa.each{|c| ba << c.to_i(16).chr}
    bytes = ba.join
  end

  # Byte string (big-endian) to big number
  def self.bytesToBignum(bytes)
    bytes.unpack('H*')[0].hex
  end

  # Byte string hex printer
  def self.printBytes(bytes, line_size = 16)
    bytes.unpack('H*')[0].scan(/.{1,#{line_size}}/).each{|s| puts(s)}
  end

end
end
