defmodule Matasano do
  @doc """
  Converts a hexadecimal `string` into a base 64 encoded string.
  """
  @spec hex_to_base64(String.t) :: String.t
  def hex_to_base64(string) do
    Base.decode16!(string, case: :mixed) |> Base.encode64()
  end
end
