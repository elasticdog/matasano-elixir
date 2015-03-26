defmodule Matasano.IO do
  @moduledoc """
  Functions handling IO, specifically related to loading data for the
  [Matasano Crypto Challenges](http://cryptopals.com/).
  """

  @doc """
  Reads file at `path` and base 64 decodes its contents.

  Returns the entire decoded file.
  """
  @spec bytes_from_base64(Path.t) :: binary
  def bytes_from_base64(path) do
    path
    |> File.stream!()
    |> Stream.map(&String.rstrip/1)
    |> Enum.join
    |> Base.decode64!
  end

  @doc """
  Returns a list containing the lines from the file at `path`.
  """
  @spec lines(Path.t) :: [binary]
  def lines(path) do
    path
    |> File.stream!()
    |> Stream.map(&String.rstrip/1)
  end

  @doc """
  Reads file at `path` and base 16 decodes each line.

  Returns a list containing the decoded lines.
  """
  @spec lines_from_hex(Path.t) :: [binary]
  def lines_from_hex(path) do
    path
    |> lines()
    |> Stream.map(&Base.decode16!(&1, case: :lower))
  end
end
