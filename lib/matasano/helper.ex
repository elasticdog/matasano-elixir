defmodule Matasano.Helper do
  @moduledoc """
  Helper functions related to solving the
  [Matasano Crypto Challenges](http://cryptopals.com/).
  """

  @doc """
  Computes the arithmetic mean of the numbers in the given `list`.

  ## Examples

      iex> Matasano.Helper.average([1, 2, 3, 4])
      2.5
  """
  @spec average([integer]) :: float
  def average(list) do
    Enum.sum(list) / length(list)
  end

  @doc """
  Returns a list containing binaries of size `n`, where each new chunk starts
  `n` bytes into the `data`.

  If there are not enough bytes to fill the final chunk, the partial chunk will
  be discarded from the result.

  ## Examples

      iex> Matasano.Helper.chunk("abcabcabc", 3)
      ["abc", "abc", "abc"]

      iex> Matasano.Helper.chunk("xxxyyyzzz", 4)
      ["xxxy", "yyzz"]
  """
  @spec chunk(binary, non_neg_integer) :: [binary]
  def chunk(data, n) do
    for <<chunk :: binary-size(n) <- data>>, do: chunk
  end

  @doc """
  Performs bit-wise XOR (exclusive or) on the data supplied.

  ## Examples

      iex> key = <<28, 1, 17, 0, 31, 1, 1, 0, 6, 26, 2, 75, 83, 83, 80, 9, 24, 28>>
      iex> Matasano.Helper.fixed_xor("hit the bull's eye", key)
      "the kid don't play"
      iex> Matasano.Helper.fixed_xor("the kid don't play", key)
      "hit the bull's eye"
  """
  @spec fixed_xor(iodata, iodata) :: binary
  def fixed_xor(a, b), do: :crypto.exor(a, b)

  @doc """
  Returns the number of differing bits between two strings of the same length.

  ## Examples

      iex> Matasano.Helper.hamming_distance("this is a test", "wokka wokka!!!")
      37
  """
  @spec hamming_distance(String.t, String.t) :: non_neg_integer
  def hamming_distance(a, b) do
    fixed_xor(a, b) |> hamming_weight
  end

  @doc """
  Returns the number of ones in the binary representation of `input`.

  ## Examples

      iex> Matasano.Helper.hamming_weight("ABC")
      7

      iex> Matasano.Helper.hamming_weight(255)
      8
      iex> Matasano.Helper.hamming_weight(256)
      1
  """
  @spec hamming_weight(String.t | non_neg_integer) :: non_neg_integer
  def hamming_weight(input)

  def hamming_weight(input) when is_binary(input) do
    input
    |> String.to_char_list
    |> Enum.reduce 0, &(hamming_weight(&1) + &2)
  end

  def hamming_weight(input) when is_number(input) do
    hamming_weight(input, 0)
  end

  defp hamming_weight(0, acc), do: acc
  defp hamming_weight(n, acc), do: hamming_weight(div(n, 2), acc + rem(n, 2))

  @doc """
  Converts a hexadecimal `string` into a base 64 encoded string.
  """
  @spec hex_to_base64(String.t) :: String.t
  def hex_to_base64(string) do
    string |> Base.decode16!(case: :mixed) |> Base.encode64
  end

  @doc """
  Generates a random string of alphanumeric characters of the requested `size`.
  """
  @spec random_alnum(non_neg_integer) :: String.t
  def random_alnum(size \\ 16) do
    alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    bound = byte_size(alnum)
    Enum.reduce 1..size, "", fn(_, acc) ->
      acc <> String.at(alnum, :random.uniform(bound) - 1)
    end
  end

  @doc """
  Performs bit-wise XOR (exclusive or) on the data supplied, repeating `key` as
  necessary to ensure equal length.

  ## Examples

      iex> Matasano.Helper.repeating_xor("a", "foobar")
      <<7, 14, 14, 3, 0, 19>>
      iex> Matasano.Helper.repeating_xor("a", <<7, 14, 14, 3, 0, 19>>)
      "foobar"

      iex> Matasano.Helper.repeating_xor("a", "hełło")
      <<9, 4, 164, 227, 164, 227, 14>>
  """
  @spec repeating_xor(iodata, iodata) :: binary
  def repeating_xor(key, message) do
    key
    |> String.codepoints
    |> Stream.cycle
    |> Enum.take(byte_size(message))
    |> :crypto.exor(message)
  end

  @doc """
  Transposes the given `list`.

  ## Examples

      iex> Matasano.Helper.transpose([[1, 2, 3], [4, 5, 6]])
      [[1, 4], [2, 5], [3, 6]]
  """
  @spec transpose([List]) :: [List]
  def transpose([[]|_]), do: []
  def transpose(list) do
    [Enum.map(list, &hd/1) | transpose(Enum.map(list, &tl/1))]
  end
end
