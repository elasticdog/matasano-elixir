defmodule Matasano do
  @doc """
  Converts a hexadecimal `string` into a base 64 encoded string.
  """
  @spec hex_to_base64(String.t) :: String.t
  def hex_to_base64(string) do
    Base.decode16!(string, case: :mixed) |> Base.encode64()
  end

  @doc """
  Performs bit-wise XOR (exclusive or) on the data supplied.
  """
  @spec fixed_xor(iodata, iodata) :: binary
  def fixed_xor(a, b), do: :crypto.exor(a, b)
end
