defmodule MatasanoTest do
  use ExUnit.Case, async: true
  doctest Matasano

  test "convert hex to base64" do
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert Matasano.hex_to_base64(hex) == base64
  end

  test "fixed xor" do
    a = Base.decode16!("1c0111001f010100061a024b53535009181c", case: :lower)
    b = Base.decode16!("686974207468652062756c6c277320657965", case: :lower)
    output = Base.decode16!("746865206b696420646f6e277420706c6179", case: :lower)
    assert Matasano.fixed_xor(a, b) == output
  end
end
