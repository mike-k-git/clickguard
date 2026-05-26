defmodule Clickguard.Event do
  @moduledoc """
  Canonical event model used by the rest of the pipeline.

  All parsers produce `%Event{}` values; all detectors consume them. Keeping
  this struct stable lets parsers and detectors evolve independently.
  """

  @type t :: %__MODULE__{
          timestamp: DateTime.t(),
          ip: :inet.ip_address() | nil,
          user_agent: String.t() | nil,
          referer: String.t() | nil,
          method: String.t(),
          path: String.t(),
          status: non_neg_integer(),
          bytes: non_neg_integer(),
          country: String.t() | nil,
          source: String.t() | nil,
          raw: String.t()
        }

  @enforce_keys [:timestamp, :method, :path, :status, :raw]
  defstruct [
    :timestamp,
    :ip,
    :user_agent,
    :referer,
    :method,
    :path,
    :status,
    :bytes,
    :country,
    :source,
    :raw
  ]

  @doc """
  Returns the IP as a string, or `nil` if the event has no IP.

  ## Examples

    iex> alias Clickguard.Event
    iex> e = %Event{ip: {127, 0, 0, 1}, timestamp: DateTime.utc_now(),
    ...>       method: "GET", path: "/", status: 200, raw: ""}
    iex> Event.ip_string(e)
    "127.0.0.1"
  """
  @spec ip_string(t()) :: String.t() | nil
  def ip_string(%__MODULE__{ip: ip}), do: format_ip(ip)

  @spec format_ip(:inet.ip_address() | nil) :: String.t() | nil
  def format_ip(nil), do: nil
  def format_ip(ip), do: ip |> :inet.ntoa() |> to_string()
end
