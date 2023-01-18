# MZI_KR2

Ruby implementing GOST 34.10-2012 ECC signature and VKO algorithms.

# Installation
   $ bundle

# Usage

 group = Gost3410Algorithm::Group::Gost256tc26a
 puts group.opts[:name]
 puts group.opts[:id]
 puts group.opts[:oid]

 coord_size = group.opts[:coord_size] # in bytes

 generator = Gost3410Algorithm::Generator.new(group)  # for sign and for vko
 verifier = Gost3410Algorithm::Verifier.new(group)    # for verify

 private_key is random number 0<n<group.order
 you can use fixed number for debugging

 private_key = SecureRandom.random_number(1..group.order-1)
 puts "private_key: #{private_key.to_s(16)}"

 public_key = group.generate_public_key private_key
 puts "public_key.x: #{public_key.x.to_s(16)}"
 puts "public_key.y: #{public_key.y.to_s(16)}"

 # Signature:

 message = 'ruby'
 digest = CryptoGost3411::Gost3411.new(coord_size).update(message).final
 Gost3410Algorithm::Converter.printBytes(digest, coord_size * 2)
 digest_num = Gost3410Algorithm::Converter.bytesToBignum(digest.reverse)
 puts "digest_num: #{digest_num.to_s(16)}"

 rnd_val is random number 0<n<group.order so as private_key
 you can use fixed number for debugging

 rand_val = SecureRandom.random_number(1..group.order-1)
 puts "rand_val: #{rand_val.to_s(16)}"

 signature = generator.sign(digest_num, private_key, rand_val)
 puts "signature.x: #{signature.x.to_s(16)}"   # x stands for r
 puts "signature.y: #{signature.y.to_s(16)}"   # y stands for s

 signature_ok = verifier.verify(digest_num, public_key, signature)
 puts "signature_ok: #{signature_ok}"

 # VKO:

 receiver_private_key = SecureRandom.random_number(1..group.order-1)
 puts "receiver_private_key: #{receiver_private_key.to_s(16)}"

 receiver_public_key = group.generate_public_key receiver_private_key
 puts "receiver_public_key.x: #{receiver_public_key.x.to_s(16)}"
 puts "receiver_public_key.y: #{receiver_public_key.y.to_s(16)}"

 ukm is random number 2**(coord_size*2)<=ukm<2**(coord_size*8)

 ukm = SecureRandom.random_number(2**(coord_size*2)..2**(coord_size*8)-1)
 puts "ukm: #{ukm.to_s(16)}"

 sender_vko = generator.vko(ukm, private_key, receiver_public_key)
 puts "sender_vko.x: #{sender_vko.x.to_s(16)}"
 puts "sender_vko.y: #{sender_vko.y.to_s(16)}"

 receiver_vko = generator.vko(ukm, receiver_private_key, public_key)
 puts "receiver_vko.x: #{receiver_vko.x.to_s(16)}"
 puts "receiver_vko.y: #{receiver_vko.y.to_s(16)}"

 puts "vko_ok: #{(sender_vko.x == receiver_vko.x) && (sender_vko.y == receiver_vko.y)}"

#### Converting GOST digest, public_key and signature strings to big numbers and vise versa

 group = Gost3410Algorithm::Group::Gost256tc26test
 coord_size = group.opts[:coord_size] # in bytes

 get tbs, signer public_key and signature byte strings from x509 certificate
 generate digest

 digest32 = CryptoGost3411::Gost3411.new(coord_size).update(tbs).final

 little-endian digest32 -> reverse -> big-endian -> BigNum

 digest32_num = Gost3410Algorithm::Converter.bytesToBignum(digest32.reverse)

 public key x||y little-endian -> reverse -> big-endian -> Point(x_num, y_num)

 public_key_x_num = Gost3410Algorithm::Converter.bytesToBignum(public_key[0...coord_size].reverse)
 public_key_y_num = Gost3410Algorithm::Converter.bytesToBignum(public_key[coord_size..-1].reverse)
 public_key_point = Gost3410Algorithm::Point.new(group, [public_key_x_num, public_key_y_num])

 signature s||r big-endian -> Point(r_num, s_num)

 signature_s_num = Gost3410Algorithm::Converter.bytesToBignum(signature[0...coord_size])
 signature_r_num = Gost3410Algorithm::Converter.bytesToBignum(signature[coord_size..-1])
 signature_point = Gost3410Algorithm::Point.new(group, [sig_r_num, sig_s_num])

 signature_point_ok = Gost3410Algorithm::Verifier.new(group).verify(digest32_num, public_key_point, signature_point)
 puts "signature_point_ok: #{signature_point_ok}"

#### Converting signature point to byte string ( s||r, big-endian):

 signature_bytes_s = Gost3410Algorithm::Converter.bignumToBytes(signature_point.x, coord_size)
 signature_bytes_r = Gost3410Algorithm::Converter.bignumToBytes(signature_point.y, coord_size)
 signature_bytes = signature_bytes_s + signature_bytes_r

#### Print signature bytes in hex (64 symbols in line)
 Gost3410Algorithm::Converter.printBytes(signature_bytes, coord_size * 2)

# List of TC 26 GOST 34.10-2012 elliptic curves:

 Gost256tc26test - id-tc26-gost-3410-2012-256-paramSetTest (former id-GostR3410-2001-TestParamSet). Use for testing only!
 Gost256tc26a    - id-tc26-gost-3410-2012-256-paramSetA (Edwards twisted curve)
 Gost256tc26b    - id-tc26-gost-3410-2012-256-paramSetB (former id-GostR3410-2001-CryptoPro-A-ParamSet)
 Gost256tc26c    - id-tc26-gost-3410-2012-256-paramSetC (former id-GostR3410-2001-CryptoPro-B-ParamSet)
 Gost256tc26d    - id-tc26-gost-3410-2012-256-paramSetD (former id-GostR3410-2001-CryptoPro-C-ParamSet)
 Gost512test     - id-tc26-gost-3410-2012-512-paramSetTest. Use for testing only!
 Gost512tc26a    - id-tc26-gost-3410-2012-512-paramSetA
 Gost512tc26b    - id-tc26-gost-3410-2012-512-paramSetB
 Gost512tc26c    - id-tc26-gost-3410-2012-512-paramSetC (Edwards twisted curve)

 You can find group by name, by id, by oid and by der_oid:


 name = 'Gost256tc26test'
 group = Gost3410Algorithm::Group.findByName(name)

 id = 'id-tc26-gost-3410-2012-256-paramSetTest'
 group = Gost3410Algorithm::Group.findById(id)

 oid = '1.2.643.7.1.2.1.1.0'
 group = Gost3410Algorithm::Group.findByOid(oid)

 der_oid = "\x06\x09\x2a\x85\x03\x07\x01\x02\x01\x01\x00"
 group = Gost3410Algorithm::Group.findByDerOid(der_oid)

# Testing

   $ rspec
