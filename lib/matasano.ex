defmodule Matasano do
  @moduledoc """
  Provides functions related to solving the
  [Matasano Crypto Challenges](http://cryptopals.com/).
  """

  ## Set 1 Challenge 1

  @doc """
  Converts a hexadecimal `string` into a base 64 encoded string.
  """
  @spec hex_to_base64(String.t) :: String.t
  def hex_to_base64(string) do
    Base.decode16!(string, case: :mixed) |> Base.encode64()
  end

  ## Set 1 Challenge 2

  @doc """
  Performs bit-wise XOR (exclusive or) on the data supplied.

  ## Examples

      iex> key = <<28, 1, 17, 0, 31, 1, 1, 0, 6, 26, 2, 75, 83, 83, 80, 9, 24, 28>>
      iex> Matasano.fixed_xor("hit the bull's eye", key)
      "the kid don't play"
      iex> Matasano.fixed_xor("the kid don't play", key)
      "hit the bull's eye"
  """
  @spec fixed_xor(iodata, iodata) :: binary
  def fixed_xor(a, b), do: :crypto.exor(a, b)
end
