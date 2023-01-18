# frozen_string_literal: true

class Verifier
  attr_reader :group

  def initialize(group)
    @group = group
  end

  def verify(hash, public_key, signature)
    @public_key = public_key
    r = signature.x
    s = signature.y
    return false if invalid_vector?(r) || invalid_vector?(s)
    (c_param(hash, public_key, r, s).x % group.order) == r
  end

  private

  def mod_inv(opt, mod)
    ModularArithmetic.invert(opt, mod)
  end

  def valid_vector?(vector)
    (1...group.order).cover? vector
  end

  def invalid_vector?(vector)
    !valid_vector?(vector)
  end

  def z_param(hash, param)
    (param * mod_inv(hash, group.order)) % group.order
  end

  def c_param(hash, public_key, r, s)
    group.generator * z_param(hash, s) + public_key * z_param(hash, -r)
  end
end

