# frozen_string_literal: true

class Generator
  attr_reader :group

  def initialize(group)
    @group = group
  end

  def sign(hash, private_key, rand_val)
    @hash = hash
    @private_key = private_key
    @rnd = rand_val
    @r = r_func
    s = s_func
    Gost3410Algorithm::Point.new self, [@r, s]
  end

  def vko(ukm, private_key, other_public_key)
    n = (group.opts[:h] * private_key * ukm) % group.order
    other_public_key * n
  end

  private

  def r_func
    (group.generator * @rnd).x % group.order
  end

  def s_func
    (@r * @private_key + @rnd * @hash) % group.order
  end

end


