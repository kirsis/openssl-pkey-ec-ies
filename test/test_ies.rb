# -*- coding: utf-8 -*-
require 'minitest/unit'
require 'openssl/pkey/ec/ies'

Minitest::Unit.autorun

class TestIES < Minitest::Unit::TestCase
  def setup
    test_key = File.read(File.expand_path(File.join(__FILE__, '..', 'test_key.pem')))
    @ec = OpenSSL::PKey::EC::IES.new(test_key, "placeholder")
  end

  def test_encrypt_then_decrypt_get_the_source_text
    source = 'いろはにほへと ちるぬるを わかよたれそ つねならむ うゐのおくやま けふこえて あさきゆめみし ゑひもせすん'
    cryptogram = @ec.public_encrypt(source)
    result = @ec.private_decrypt(cryptogram)
    assert_equal source, result
  end
end
