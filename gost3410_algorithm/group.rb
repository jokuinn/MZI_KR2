# frozen_string_literal: true

class Group
  attr_reader :opts, :generator, :a, :b, :gx, :gy, :order, :p

  def initialize(opts)
    @opts = opts
    @name = opts.fetch(:name)
    @p = opts[:p]
    @a = opts[:a]
    @b = opts[:b]
    @gx = opts[:gx]
    @gy = opts[:gy]
    @order = opts[:n]
    @cofactor = opts[:h]
    @generator = Gost3410Algorithm::Point.new self, [gx, gy]
  end

  NAMES = %w[
     Gost256tc26test
     Gost256tc26a
     Gost256tc26b
     Gost256tc26c
     Gost256tc26d
     Gost512tc26test
     Gost512tc26a
     Gost512tc26b
     Gost512tc26c
   ].freeze

  NAMES.each do |name|
    require_relative "./group/#{name.downcase}"
  end

  def self.findByOid(oid)
    group = nil
    NAMES.each do |n|
      g = Object.const_get("Gost3410Algorithm::Group::#{n}")
      if g.opts[:oid] == oid then
        group = g
        break
      end
      if (g.opts[:cp_oid] != nil) && (g.opts[:cp_oid] == oid) then
        group = g
        break
      end
    end
    group
  end

  def self.findByDerOid(der_oid)
    group = nil
    NAMES.each do |n|
      g = Object.const_get("Gost3410Algorithm::Group::#{n}")
      if g.opts[:der_oid] == der_oid then
        group = g
        break
      end
      if (g.opts[:cp_der_oid] != nil) && (g.opts[:cp_der_oid] == der_oid) then
        group = g
        break
      end
    end
    group
  end

  def self.findById(id)
    group = nil
    NAMES.each do |n|
      g = Object.const_get("Gost3410Algorithm::Group::#{n}")
      if g.opts[:id] == id then
        group = g
        break
      end
      if (g.opts[:cp_id] != nil) && (g.opts[:cp_id] == id) then
        group = g
        break
      end
    end
    group
  end

  def self.findByName(name)
    group = nil
    NAMES.each do |n|
      g = Object.const_get("Gost3410Algorithm::Group::#{n}")
      if g.opts[:name] == name then
        group = g
        break
      end
    end
    group
  end

  def generate_public_key(private_key)
    generator * private_key
  end

end
