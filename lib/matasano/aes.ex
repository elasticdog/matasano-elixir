defmodule Matasano.AES do
  @moduledoc """
  Functions related to encrypting and decrypting data using the Advanced
  Encryption Standard (AES).
  """

  import Matasano.Helper

  @doc """
  Encrypt the given `data` with AES-128 in ECB mode using `key`.

  PKCS#7 padding will not be added to `data` if you explicitly pass the
  `:nopad` option.
  """
  @spec encrypt_aes_128_ecb(iodata, String.t, [atom]) :: String.t
  def encrypt_aes_128_ecb(data, key, opts \\ []) do
    # I'm going to cheat here and shell out to OpenSSL until Erlang OTP 18 is
    # released, which added code to the crypto module for AES-128 in ECB mode.
    path = Path.join(System.tmp_dir!, random_alnum) <> ".tmp"

    if Enum.member?(opts, :nopad) do
      File.write!(path, data)
    else
      File.write!(path, pad_pkcs7(data, 16))
    end

    args = ["aes-128-ecb", "-in", path, "-K", Base.encode16(key), "-nopad"]
    {output, _exit_status} = System.cmd("openssl", args)
    File.rm!(path)

    output
  end

  @doc """
  Decrypt the given `data` with AES-128 in ECB mode using `key`.

  PKCS#7 padding will be left intact if you explicitly pass the `:nopad`
  option.
  """
  @spec decrypt_aes_128_ecb(iodata, String.t, [atom]) :: String.t
  def decrypt_aes_128_ecb(data, key, opts \\ []) do
    # I'm going to cheat here and shell out to OpenSSL until Erlang OTP 18 is
    # released, which added code to the crypto module for AES-128 in ECB mode.
    path = Path.join(System.tmp_dir!, random_alnum) <> ".tmp"
    File.write!(path, data)

    args = ["aes-128-ecb", "-in", path, "-K", Base.encode16(key), "-d", "-nopad"]
    {output, _exit_status} = System.cmd("openssl", args)
    File.rm!(path)

    if Enum.member?(opts, :nopad) do
      output
    else
      unpad_pkcs7(output)
    end
  end

  @doc """
  Returns the first element from `collection` that has a repeated block of the
  given `blocksize`.

  This is likely to be an indication of encryption with AES in ECB mode.
  """
  @spec detect_aes_in_ecb([binary], non_neg_integer) :: binary
  def detect_aes_in_ecb(collection, blocksize) do
    Enum.find collection, &repeated_block?(&1, blocksize)
  end

  @doc """
  Detects if the `string` has a repeated block of the given `blocksize`.

      iex> Matasano.AES.repeated_block?("abcabc", 2)
      false
      iex> Matasano.AES.repeated_block?("abcabc", 3)
      true
  """
  @spec repeated_block?(String.t, non_neg_integer) :: boolean
  def repeated_block?(string, blocksize) do
    blocks = chunk(string, blocksize)
    block_set = Enum.reduce blocks, %HashSet{}, &HashSet.put(&2, &1)

    length(blocks) != HashSet.size(block_set)
  end

  @doc """
  Pad the `message` by extending it to the nearest `blocksize` boundary,
  appending the number of bytes of padding to the end of the block.

  If the original `message` is a multiple of `blocksize`, an additional block
  of bytes with value `blocksize` is added.

  ## Examples

      iex> Matasano.AES.pad_pkcs7("HELLO", 4)
      <<72, 69, 76, 76, 79, 3, 3, 3>>
      iex> Matasano.AES.pad_pkcs7("HELLO", 5)
      <<72, 69, 76, 76, 79, 5, 5, 5, 5, 5>>
  """
  @spec pad_pkcs7(String.t, non_neg_integer) :: String.t
  def pad_pkcs7(message, blocksize) do
    pad = blocksize - rem(byte_size(message), blocksize)
    message <> to_string(List.duplicate(pad, pad))
  end

  @doc """
  Remove the PKCS#7 padding from the end of `data`.

  ## Examples

      iex> Matasano.AES.unpad_pkcs7(<<72, 69, 76, 76, 79, 3, 3, 3>>)
      "HELLO"
  """
  def unpad_pkcs7(data) do
    <<pad>> = binary_part(data, byte_size(data), -1)
    binary_part(data, 0, byte_size(data) - pad)
  end

  @doc """
  Encrypt the given `data` with AES-128 in CBC mode using `key` and `iv`.
  """
  @spec encrypt_aes_128_cbc(iodata, String.t, binary) :: String.t
  def encrypt_aes_128_cbc(data, key, iv) do
    blocks = data |> pad_pkcs7(16) |> chunk(16)
    encrypt_cbc([iv|blocks], key, [])
  end

  defp encrypt_cbc([], _key, acc), do: acc |> Enum.reverse |> Enum.join

  defp encrypt_cbc([iv,head|tail], key, []) do
    block = head |> fixed_xor(iv) |> encrypt_aes_128_ecb(key, [:nopad])
    encrypt_cbc(tail, key, [block])
  end

  defp encrypt_cbc([head|tail], key, acc) do
    block = head |> fixed_xor(hd(acc)) |> encrypt_aes_128_ecb(key, [:nopad])
    encrypt_cbc(tail, key, [block|acc])
  end

  @doc """
  Decrypt the given `data` with AES-128 in CBC mode using `key` and `iv`.
  """
  @spec decrypt_aes_128_cbc(iodata, String.t, binary) :: String.t
  def decrypt_aes_128_cbc(data, key, iv) do
    rev_blocks = [iv|chunk(data, 16)] |> Enum.reverse

    decrypt_cbc(rev_blocks, key, []) |> unpad_pkcs7
  end

  defp decrypt_cbc([_], _key, acc), do: Enum.join(acc)

  defp decrypt_cbc([left,right|tail], key, acc) do
    block = decrypt_aes_128_ecb(left, key, [:nopad]) |> fixed_xor(right)
    rest = [right|tail]
    decrypt_cbc(rest, key, [block|acc])
  end

  @doc """
  Encrypts `plaintext` using AES-128 with a randomly chosen mode/key/IV.

  Also prepend and append 5 to 10 random bytes (count also chosen randomly) to
  the plaintext.
  """
  def encryption_oracle(plaintext) do
    pre_data  = :crypto.rand_bytes(:crypto.rand_uniform(5, 11))
    post_data = :crypto.rand_bytes(:crypto.rand_uniform(5, 11))
    data = pre_data <> plaintext <> post_data

    random_mode = :random.uniform(2)
    random_key  = :crypto.rand_bytes(16)

    case random_mode do
      1 ->
        encrypt_aes_128_ecb(data, random_key)
      2 ->
        random_iv = :crypto.rand_bytes(16)
        encrypt_aes_128_cbc(data, random_key, random_iv)
    end
  end

  @doc """
  Returns the most likely AES-128 mode (ECB or CBC) used to encrypt `data`.
  """
  def detect_aes_128_mode(data) do
    if repeated_block?(data, 16) do
      :ebs
    else
      :cbc
    end
  end
end
