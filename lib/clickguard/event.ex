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

  @doc """
  Returns the {ip, ua} key as a string.
  Separator is `|` so that `IP` and `UA` never collide.

  ## Examples

    iex> alias Clickguard.Event
    iex> e = %Event{timestamp: ~U[2016-06-24 13:26:08.003Z], ip: {8193, 3512, 34211, 0, 0, 35374, 880, 29492}, 
    ...>   user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0", 
    ...>   referer: "https://google.com", method: "GET", path: "/", status: 200, bytes: 0, country: nil, source: nil, raw: ""}
    iex> Event.session_key(e)
    "2001:db8:85a3::8a2e:370:7334|Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0"
  """

  @spec session_key(t()) :: String.t()
  def session_key(%__MODULE__{} = event) do
    "#{format_ip(event.ip)}|#{event.user_agent || ""}"
  end

  @spec sample([%__MODULE__{}]) :: [%__MODULE__{}]
  def sample(events) when length(events) < 5, do: events
  def sample(events), do: Enum.take(events, 3) ++ Enum.take(events, -2)
end
