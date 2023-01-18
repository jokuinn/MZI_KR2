# frozen_string_literal: true

require 'minitest/autorun'
require 'gost3410_algorithm'

class Gost3410AlgorithmTest < Minitest::Test
  describe Gost3410Algorithm do
    context 'gost3410_algorithm' do
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
        context name do
          let(:group) { Object.const_get("Gost3410Algorithm::Group::#{name}") }
          let(:private_key) { SecureRandom.random_number(1..group.order-1) }
          let(:public_key) { group.generate_public_key private_key }
          let(:message) { Faker::Lorem.sentence(3) }
          let(:coord_size) { group.opts[:coord_size] }
          let(:digest) { CryptoGost3411::Gost3411.new(coord_size).update(message).final }
          let(:digest_num) { Gost3410Algorithm::Converter.bytesToBignum(digest.reverse) }
          let(:generator) { Gost3410Algorithm::Generator.new(group) }
          let(:rand_val) { SecureRandom.random_number(1..group.order-1) }
          let(:signature) { generator.sign(digest_num, private_key, rand_val) }
          let(:verifier) { Gost3410Algorithm::Verifier.new(group) }
          let(:another_message) { Faker::Lorem.sentence(2) }
          let(:another_digest) { CryptoGost3411::Gost3411.new(coord_size).update(another_message).final}
          let(:another_digest_num) { Gost3410Algorithm::Converter.bytesToBignum(another_digest.reverse) }
          let(:receiver_private_key) { SecureRandom.random_number(1..group.order-1) }
          let(:receiver_public_key) { group.generate_public_key receiver_private_key }
          let(:ukm) { SecureRandom.random_number(2**(coord_size*2)..2**(coord_size*8)-1) }
          let(:sender_vko) { generator.vko(ukm, private_key, receiver_public_key) }
          let(:receiver_vko) { generator.vko(ukm, receiver_private_key, public_key) }

          it 'find group by name' do
            expect(Gost3410Algorithm::Group.findByName(group.opts[:name]) == group).to be_truthy
          end

          it 'find group by id' do
            expect(Gost3410Algorithm::Group.findById(group.opts[:id]) == group).to be_truthy
          end

          it 'find group by oid' do
            expect(Gost3410Algorithm::Group.findByOid(group.opts[:oid]) == group).to be_truthy
          end

          it 'find group by der oid' do
            expect(Gost3410Algorithm::Group.findByDerOid(group.opts[:der_oid]) == group).to be_truthy
          end

          it 'has valid signature' do
            expect(verifier.verify(digest_num, public_key, signature)).to be_truthy
          end

          it 'has invalid signature for changed message' do
            expect(verifier.verify(another_digest_num, public_key, signature)).to be_falsy
          end

          it 'sender VKO equals to receiver VKO' do
            expect((sender_vko.x == receiver_vko.x) && (sender_vko.y == receiver_vko.y)).to be_truthy
          end
        end
      end
    end
  end

end
