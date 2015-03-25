defmodule Matasano do
  @moduledoc """
  Provides functions related to solving the
  [Matasano Crypto Challenges](http://cryptopals.com/).
  """

  import Matasano.Language

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
    {_key, plaintext, _score} = best_xor_score(ciphertext)
    plaintext
  end

  @doc """
  Returns data regarding the single-byte XOR cipher key that is most likely to
  decrypt `ciphertext` into English text.
  """
  @spec best_xor_score(String.t) :: {String.t, String.t, float}
  def best_xor_score(ciphertext) do
    all_possible_bytes =
      0..255 |> Enum.to_list |> IO.iodata_to_binary |> String.codepoints

    best_xor_score(ciphertext, all_possible_bytes)
  end

  @doc """
  Returns data regarding the candidate XOR cipher key that is most likely to
  decrypt `ciphertext` into English text.
  """
  @spec best_xor_score(String.t, [String.t]) :: {String.t, String.t, float}
  def best_xor_score(ciphertext, candidates) do
    Enum.map(candidates, fn key ->
      plaintext = repeating_xor(key, ciphertext)
      score = english_score(plaintext)
      {key, plaintext, score}
    end)
    |> Enum.max_by(fn {_, _, score} -> score end)
  end

  @doc """
  Performs bit-wise XOR (exclusive or) on the data supplied, repeating `key` as
  necessary to ensure equal length.

  ## Examples

      iex> Matasano.repeating_xor("a", "foobar")
      <<7, 14, 14, 3, 0, 19>>
      iex> Matasano.repeating_xor("a", <<7, 14, 14, 3, 0, 19>>)
      "foobar"

      iex> Matasano.repeating_xor("a", "hełło")
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
  Returns the element from `collection` that is most likely to be English text
  after decrypting it with a XOR cipher.
  """
  @spec detect_single_byte_xor([binary]) :: String.t
  def detect_single_byte_xor(collection) do
    {:ok, agent} = Agent.start_link fn -> [] end

    parallel_map collection, fn(ciphertext) ->
      best = best_xor_score(ciphertext)
      Agent.update(agent, fn list ->
        [best|list]
      end)
    end

    {_key, plaintext, _score} =
      Agent.get(agent, &(&1)) |> Enum.max_by(fn {_, _, score} -> score end)

    plaintext
  end

  defp parallel_map(collection, function) do
    parent = self()

    collection
    |>
    Enum.map(fn(element) ->
      spawn_link fn -> send parent, {function.(element), self()} end
    end)
    |>
    Enum.map(fn(pid) ->
      receive do {result, ^pid} -> result end
    end)
  end

  @doc """
  Returns the key that is most likely to produce English text when XOR'd with
  `ciphertext`.
  """
  @spec break_repeating_key_xor(String.t) :: String.t
  def break_repeating_key_xor(ciphertext) do
    keysize = guess_keysize(ciphertext)

    ciphertext
    |> key_parts(keysize)
    |>
    Enum.map(fn block ->
      {key, _plaintext, _score} = best_xor_score(block)
      key
    end)
    |> Enum.join()
  end

  @doc """
  Tests each of the `guesses` as a key size against the `message` to determine
  which one has the lowest normalized Hamming distance.
  """
  @spec guess_keysize(String.t, [non_neg_integer]) :: non_neg_integer
  def guess_keysize(message, guesses \\ 2..40) do
    guesses |> Enum.min_by(&normalized_hamming_distance(message, &1))
  end

  defp normalized_hamming_distance(string, keysize) do
    if byte_size(string) < (keysize * 2) do
      raise ArgumentError, message: "keysize too large for the given string"
    end

    blocks = chunk(string, keysize)
    distances = Enum.map Enum.chunk(blocks, 2), fn [a, b] ->
      hamming_distance(a, b)
    end
    average(distances) / keysize
  end

  @doc """
  Returns a list containing `n` strings, where each new chunk starts `n` bytes
  into the `string`.

  If there are not enough bytes to fill the final chunk, the partial chunk will
  be discarded from the result.

  ## Examples

      iex> Matasano.chunk("abcabcabc", 3)
      ["abc", "abc", "abc"]

      iex> Matasano.chunk("xxxyyyzzz", 4)
      ["xxxy", "yyzz"]
  """
  @spec chunk(String.t, non_neg_integer) :: [String.t]
  def chunk(string, n) do
    string |> String.to_char_list |> Stream.chunk(n) |> Enum.map(&to_string/1)
  end

  @doc """
  Returns the number of differing bits between two strings of the same length.

  ## Examples

      iex> Matasano.hamming_distance("this is a test", "wokka wokka!!!")
      37
  """
  @spec hamming_distance(String.t, String.t) :: non_neg_integer
  def hamming_distance(a, b) do
    fixed_xor(a, b) |> hamming_weight()
  end

  @doc """
  Returns the number of ones in the binary representation of `input`.

  ## Examples

      iex> Matasano.hamming_weight("ABC")
      7
  """
  @spec hamming_weight(String.t | non_neg_integer) :: non_neg_integer
  def hamming_weight(input) when is_binary(input) do
    input
    |> String.to_char_list()
    |> Enum.reduce 0, &(Matasano.hamming_weight(&1) + &2)
  end
  def hamming_weight(input) when is_number(input) do
    hamming_weight(input, 0)
  end

  defp hamming_weight(0, acc), do: acc
  defp hamming_weight(n, acc), do: hamming_weight(div(n, 2), acc + rem(n, 2))

  @doc """
  Computes the arithmetic mean of the numbers in the given `list`.

  ## Examples

      iex> Matasano.average([1, 2, 3, 4])
      2.5
  """
  def average(list) do
    Enum.sum(list) / length(list)
  end

  @doc """
  Splits the `message` into blocks of `keysize` length, and then transposes the
  list.

  ## Examples

      iex> Matasano.key_parts("abcabcabc", 3)
      ["aaa", "bbb", "ccc"]
  """
  def key_parts(message, keysize) do
    message
    |> chunk(keysize)
    |> Stream.map(&String.to_char_list/1)
    |> transpose
    |> Enum.map(&to_string/1)
  end

  @doc """
  Transposes the given `list`.

  ## Examples

      iex> Matasano.transpose([[1, 2, 3], [4, 5, 6]])
      [[1, 4], [2, 5], [3, 6]]
  """
  @spec transpose([List]) :: [List]
  def transpose([[]|_]), do: []
  def transpose(list) do
    [Enum.map(list, &hd/1) | transpose(Enum.map(list, &tl/1))]
  end
end