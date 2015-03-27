defmodule MatasanoTest do
  use ExUnit.Case, async: true
  doctest Matasano

  @tag :set1
  test "set 1 challenge 1 - convert hex to base64" do
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    assert Matasano.hex_to_base64(hex) == base64
  end

  @tag :set1
  test "set 1 challenge 2 - fixed xor" do
    a = Base.decode16!("1c0111001f010100061a024b53535009181c", case: :lower)
    b = Base.decode16!("686974207468652062756c6c277320657965", case: :lower)
    output = Base.decode16!("746865206b696420646f6e277420706c6179", case: :lower)

    assert Matasano.fixed_xor(a, b) == output
  end

  @tag :set1
  test "set 1 challenge 3 - single-byte xor cipher" do
    ciphertext = Base.decode16!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", case: :lower)
    plaintext = "Cooking MC's like a pound of bacon"

    assert Matasano.decrypt_single_byte_xor(ciphertext) == plaintext
  end

  @tag :set1
  test "set 1 challenge 4 - detect single-character xor" do
    data = Matasano.IO.lines_from_hex(Path.join("data", "4.txt"))
    plaintext = "Now that the party is jumping\n"

    assert Matasano.detect_single_byte_xor(data) == plaintext
  end

  @tag :set1
  test "set 1 challenge 5 - implement repeating-key xor" do
    key = "ICE"
    message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    output = Base.decode16!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", case: :lower)

    assert Matasano.repeating_xor(key, message) == output
  end

  @tag :set1
  test "set 1 challenge 6 - break repeating-key xor" do
    data = Matasano.IO.bytes_from_base64(Path.join("data", "6.txt"))
    key = "Terminator X: Bring the noise"

    assert Matasano.break_repeating_key_xor(data) == key
  end

  @tag :set1
  test "set 1 challenge 7 - aes in ecb mode" do
    datafile = Path.join("data", "7.txt")
    key = Base.encode16("YELLOW SUBMARINE")
    plaintext = File.read!(Path.join("data", "play-that-funky-music.txt"))

    assert Matasano.decrypt_aes_128_ecb(datafile, key) == plaintext
  end

  @tag :set1
  test "set 1 challenge 8 - detect aes in ecb mode" do
    data = Matasano.IO.lines(Path.join("data", "8.txt"))
    output = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

    assert Matasano.detect_aes_in_ecb(data, 32) == output
  end

  @tag :set2
  test "set 2 challenge 9 - implement pkcs#7 padding" do
    message = "YELLOW SUBMARINE"
    blocksize = 20
    output = "YELLOW SUBMARINE\x04\x04\x04\x04"

    assert Matasano.pkcs7_padding(message, blocksize) == output
  end
end
