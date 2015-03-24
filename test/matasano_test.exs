defmodule MatasanoTest do
  use ExUnit.Case, async: true
  doctest Matasano

  test "set 1 challenge 1 - convert hex to base64" do
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    assert Matasano.hex_to_base64(hex) == base64
  end

  test "set 1 challenge 2 - fixed xor" do
    a = Base.decode16!("1c0111001f010100061a024b53535009181c", case: :lower)
    b = Base.decode16!("686974207468652062756c6c277320657965", case: :lower)
    output = Base.decode16!("746865206b696420646f6e277420706c6179", case: :lower)

    assert Matasano.fixed_xor(a, b) == output
  end

  test "set 1 challenge 3 - single-byte xor cipher" do
    ciphertext = Base.decode16!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", case: :lower)
    plaintext = "Cooking MC's like a pound of bacon"

    assert Matasano.decrypt_single_byte_xor(ciphertext) == plaintext
  end

  test "set 1 challenge 4 - detect single-character xor" do
    data = Path.join("data", "4.txt")
    plaintext = "Now that the party is jumping\n"

    assert Matasano.detect_single_byte_xor(data) == plaintext
  end

  test "set 1 challenge 5 - implement repeating-key xor" do
    key = "ICE"
    message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    output = Base.decode16!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", case: :lower)

    assert Matasano.repeating_xor(key, message) == output
  end

  test "set 1 challenge 6 - break repeating-key xor" do
    data = Matasano.bytes_from_base64(Path.join("data", "6.txt"))
    key = "Terminator X: Bring the noise"

    assert Matasano.break_repeating_key_xor(data) == key
  end
end
