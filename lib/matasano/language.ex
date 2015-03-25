defmodule Matasano.Language do
  @moduledoc """
  Functions related to detecting the language of text.
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
  Calculates a score based on the probability of `string` being English text.

  The higher the score, the higher the likelihood of the text being English.
  """
  @spec english_score(String.t) :: float
  def english_score(string) do
    language_score(string, @english_distribution)
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
  Calculates the relative frequency of characters in `string`.

  Returns a dictionary of characters mapping to relative frequency values.
  All characters are normalized to uppercase.

  ## Examples

      iex> Matasano.Language.relative_frequency("Hełło world!")
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

      iex> Matasano.Language.character_frequency("Hełło world!")
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
end
