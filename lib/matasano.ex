defmodule Matasano do
  @moduledoc """
  Provides functions related to solving the
  [Matasano Crypto Challenges](http://cryptopals.com/).
  """

  # https://en.wikipedia.org/wiki/Letter_frequency
  # http://www.data-compression.com/english.html
  @english_distribution %{
    "A" => 0.0651738,
    "B" => 0.0124248,
    "C" => 0.0217339,
    "D" => 0.0349835,
    "E" => 0.1041442,
    "F" => 0.0197881,
    "G" => 0.0158610,
    "H" => 0.0492888,
    "I" => 0.0558094,
    "J" => 0.0009033,
    "K" => 0.0050529,
    "L" => 0.0331490,
    "M" => 0.0202124,
    "N" => 0.0564513,
    "O" => 0.0596302,
    "P" => 0.0137645,
    "Q" => 0.0008606,
    "R" => 0.0497563,
    "S" => 0.0515760,
    "T" => 0.0729357,
    "U" => 0.0225134,
    "V" => 0.0082903,
    "W" => 0.0171272,
    "X" => 0.0013692,
    "Y" => 0.0145984,
    "Z" => 0.0007836,
    " " => 0.1918182,
  }

  @doc """
  Converts a hexadecimal `string` into a base 64 encoded string.
  """
  @spec hex_to_base64(String.t) :: String.t
  def hex_to_base64(string) do
    Base.decode16!(string, case: :mixed) |> Base.encode64()
  end

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

  @doc """
  Decrypts `ciphertext` by testing all possible single byte values as a key to
  XOR against.
  """
  @spec decrypt_single_byte_xor(String.t) :: String.t
  def decrypt_single_byte_xor(ciphertext) do
    candidates =
      0..255 |> Enum.to_list |> IO.iodata_to_binary |> String.graphemes

    {_key, plaintext, _score} = best_xor_score(ciphertext, candidates)
    plaintext
  end

  @doc """
  Returns data regarding the candidate XOR cipher key that is most likely to
  decrypt `ciphertext` into English text.
  """
  @spec best_xor_score(String.t, [String.t]) :: {String.t, String.t, float}
  def best_xor_score(ciphertext, candidates) do
    key = Enum.max_by candidates, fn key ->
      language_score(repeating_xor(key, ciphertext), @english_distribution)
    end
    plaintext = repeating_xor(key, ciphertext)
    score = language_score(plaintext, @english_distribution)
    {key, plaintext, score}
  end

  @doc """
  Performs bit-wise XOR (exclusive or) on the data supplied, repeating `key` as
  necessary to ensure equal length.

  ## Examples

      iex> Matasano.repeating_xor("a", "foobar")
      <<7, 14, 14, 3, 0, 19>>
      iex> Matasano.repeating_xor("a", <<7, 14, 14, 3, 0, 19>>)
      "foobar"
  """
  @spec repeating_xor(iodata, iodata) :: binary
  def repeating_xor(key, message) do
    key
    |> String.graphemes
    |> Stream.cycle
    |> Enum.take(String.length(message))
    |> :crypto.exor(message)
  end

  @doc """
  Calculates a score based on the probability of `string` being text of
  a particular language.

  The higher the score, the higher the likelihood of the text being written in
  the language as defined by the given `language_distribution` of characters.
  """
  @spec language_score(String.t, Map) :: float
  def language_score(string, language_distribution) do
    bhattacharyya_coefficient(language_distribution, relative_frequency(string))
  end

  @doc """
  Calculates the relative frequency of characters in `string`.

  Returns a dictionary of characters mapping to relative frequency values.
  All characters are normalized to uppercase.

  ## Examples

      iex> Matasano.relative_frequency("Hełło world!")
      %{" " => 0.08333333333333333, "!" => 0.08333333333333333,
        "D" => 0.08333333333333333, "E" => 0.08333333333333333,
        "H" => 0.08333333333333333, "L" => 0.08333333333333333,
        "O" => 0.16666666666666666, "R" => 0.08333333333333333,
        "W" => 0.08333333333333333, "Ł" => 0.16666666666666666}
  """
  @spec relative_frequency(String.t) :: Map
  def relative_frequency(string) do
    counts = character_frequency(string)
    total = String.length(string)
    if total < 1 do
      raise ArgumentError, message: "invalid argument string"
    end

    Enum.reduce counts, %{}, fn({char, count}, acc) ->
      Map.put(acc, char, count / total)
    end
  end

  @doc """
  Counts the frequency of characters in `string`.

  Returns a dictionary of characters mapping to count values.
  All characters are normalized to uppercase.

  ## Examples

      iex> Matasano.character_frequency("Hełło world!")
      %{" " => 1, "!" => 1, "D" => 1, "E" => 1, "H" => 1, "L" => 1, "O" => 2,
        "R" => 1, "W" => 1, "Ł" => 2}
  """
  @spec character_frequency(String.t) :: Map
  def character_frequency(string) do
    string
    |> String.upcase
    |> String.graphemes
    |>
    Enum.reduce %{}, fn(grapheme, counts) ->
      Map.update(counts, grapheme, 1, &(&1 + 1))
    end
  end

  @doc """
  Measures the amount of overlap between two statistical samples.

  The Bhattacharyya coefficient will be 0.0 if there is no overlap.
  """
  @spec bhattacharyya_coefficient(Map, Map) :: float
  def bhattacharyya_coefficient(left, right) do
    Enum.reduce left, 0, fn({key, left_value}, acc) ->
      right_value = Map.get(right, key, 0)
      :math.sqrt(left_value * right_value) + acc
    end
  end

  @doc """
  Reads file at `path` and returns the line that is most likely to be English
  text after decrypting it with a XOR cipher.
  """
  @spec detect_single_byte_xor(Path.t) :: String.t
  def detect_single_byte_xor(path) do
    candidates =
      0..255 |> Enum.to_list |> IO.iodata_to_binary |> String.graphemes

    File.stream!(path)
    |>
    Stream.map(&Base.decode16!(String.rstrip(&1), case: :lower))
    |>
    Enum.max_by(fn ciphertext ->
      {_key, _plaintext, score} = best_xor_score(ciphertext, candidates)
      score
    end)
    |>
    decrypt_single_byte_xor()
  end
end
