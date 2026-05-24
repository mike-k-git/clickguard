defmodule Clickguard.Parser.CLF do
  @moduledoc """
  Parser for the Apache/Nginx Combined Log Format.

  Format string (Apache Combined Log Format):

    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"

  Example line:

    127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)" 
  """

  @behaviour Clickguard.Parser

  alias Clickguard.Event

  # Named-capture regex. The two trailing quoted fields are optional so that
  # Commmon Log Format (without referer / user-agent) still parses cleanly.
  @line_re ~r"""
  ^
  (?<ip>\S+)\s+
  \S+\s+
  \S+\s+
  \[(?<time>[^\]]+)\]\s+
  "(?<request>[^"]*)"\s+
  (?<status>\d{3})\s+
  (?<bytes>\d+|-)
  (?:\s+"(?<referer>[^"]*)"\s+"(?<ua>[^"]*)")?
  \s*$
  """x

  @doc """
  Parses a single CLF/Combined log line.

  ## Examples

    iex> {:ok, e} = Clickguard.Parser.CLF.parse(
    ...>  ~s(127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.1" 200 512))
    iex> e.method
    "GET"
    iex> e.status
    200

  """
  @impl true
  def parse(""), do: {:error, :empty}

  def parse(line) when is_binary(line) do
    case Regex.named_captures(@line_re, line) do
      nil ->
        {:error, :malformed}

      %{} = caps ->
        with {:ok, ip} <- parse_ip(caps["ip"]),
             {:ok, ts} <- parse_time(caps["time"]),
             {:ok, method, path} <- parse_request(caps["request"]),
             {:ok, status} <- parse_int(caps["status"], :status),
             {:ok, bytes} <- parse_bytes(caps["bytes"]) do
          {:ok,
           %Event{
             timestamp: ts,
             ip: ip,
             user_agent: nilify(caps["ua"]),
             referer: nilify(caps["referer"]),
             method: method,
             path: path,
             status: status,
             bytes: bytes,
             raw: line
           }}
        end
    end
  end

  defp nilify(""), do: nil
  defp nilify(nil), do: nil
  defp nilify(str), do: str

  defp parse_ip(str) do
    case :inet.parse_address(String.to_charlist(str)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> {:error, {:bad_field, :ip}}
    end
  end

  defp parse_int(str, field) do
    case Integer.parse(str) do
      {n, ""} -> {:ok, n}
      _ -> {:error, {:bad_field, field}}
    end
  end

  defp parse_bytes("-"), do: {:ok, 0}
  defp parse_bytes(str), do: parse_int(str, :bytes)

  defp parse_request(req) do
    # "METHOD path HTTP/version" - split on first and last space so that
    # paths containing spaces (rare, but possible) survive.
    case String.split(req, " ", parts: 3) do
      [method, path, "HTTP/" <> _] -> {:ok, method, path}
      [method, path, _other] -> {:ok, method, path}
      _ -> {:error, {:bad_field, :request}}
    end
  end

  # CLF time: "10/Oct/2000:13:55:36 -0700"
  defp parse_time(str) do
    with [date_part, tz_part] <- String.split(str, " ", parts: 2),
         [d, mon, y, h, m, s] <- String.split(date_part, ["/", ":"]),
         {:ok, month} <- month_to_int(mon),
         {day, ""} <- Integer.parse(d),
         {year, ""} <- Integer.parse(y),
         {hour, ""} <- Integer.parse(h),
         {min, ""} <- Integer.parse(m),
         {sec, ""} <- Integer.parse(s),
         {:ok, offset_sec} <- parse_tz_offset(tz_part),
         {:ok, naive} <- NaiveDateTime.new(year, month, day, hour, min, sec),
         unix <- NaiveDateTime.diff(naive, ~N[1970-01-01 00:00:00]) - offset_sec do
      {:ok, DateTime.from_unix!(unix)}
    else
      _ -> {:error, {:bad_field, :time}}
    end
  end

  defp parse_tz_offset(<<sign, hh::binary-size(2), mm::binary-size(2)>>) when sign in [?+, ?-] do
    with {h, ""} <- Integer.parse(hh),
         {m, ""} <- Integer.parse(mm) do
      total = h * 3600 + m * 60
      {:ok, if(sign == ?-, do: -total, else: total)}
    else
      _ -> :error
    end
  end

  defp parse_tz_offset(_), do: :error

  @months %{
    "Jan" => 1,
    "Feb" => 2,
    "Mar" => 3,
    "Apr" => 4,
    "May" => 5,
    "Jun" => 6,
    "Jul" => 7,
    "Aug" => 8,
    "Sep" => 9,
    "Oct" => 10,
    "Nov" => 11,
    "Dec" => 12
  }

  defp month_to_int(mon) do
    case Map.fetch(@months, mon) do
      {:ok, n} -> {:ok, n}
      :error -> :error
    end
  end
end
