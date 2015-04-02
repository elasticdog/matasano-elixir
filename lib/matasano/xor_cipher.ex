defmodule Matasano.XorCipher do
  @moduledoc """
  Functions related to encrypting and decrypting data using a XOR Cipher.
  """

  import Matasano.Helper
  import Matasano.Language

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
    candidates
    |> Stream.map(&xor_score(&1, ciphertext))
    |> Enum.max_by fn {_, _, score} -> score end
  end

  @doc """
  Returns data regarding the result of XOR cipher decryption of `ciphertext`
  using the `key`.
  """
  def xor_score(key, ciphertext) do
    plaintext = repeating_xor(key, ciphertext)
    score = english_score(plaintext)
    {key, plaintext, score}
  end

  @doc """
  Returns the element from `collection` that is most likely to be English text
  after decrypting it with a XOR cipher.
  """
  @spec detect_single_byte_xor([binary]) :: String.t
  def detect_single_byte_xor(collection) do
    scores = pmap collection, &best_xor_score/1

    {_key, plaintext, _score} = Enum.max_by scores, fn {_, _, score} -> score end

    plaintext
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
    |> pmap(&best_single_byte_key/1)
    |> Enum.join
  end

  defp best_single_byte_key(block) do
    {key, _plaintext, _score} = best_xor_score(block)
    key
  end

  @doc """
  Tests each of the `guesses` as a key size against the `message` to determine
  which one has the lowest normalized Hamming distance.
  """
  @spec guess_keysize(String.t, [non_neg_integer]) :: non_neg_integer
  def guess_keysize(message, guesses \\ 2..40) do
    Enum.min_by guesses, &normalized_hamming_distance(message, &1)
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
  Splits the `message` into blocks of `keysize` length, and then transposes the
  list.

  ## Examples

      iex> Matasano.XorCipher.key_parts("abcabcabc", 3)
      ["aaa", "bbb", "ccc"]
  """
  @spec key_parts(String.t, non_neg_integer) :: [String.t]
  def key_parts(message, keysize) do
    message
    |> chunk(keysize)
    |> Stream.map(&String.to_char_list/1)
    |> transpose
    |> Enum.map &to_string/1
  end
end
