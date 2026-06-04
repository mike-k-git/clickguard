defmodule Clickguard.EventBuilder do
  @moduledoc false

  alias Clickguard.Event

  def event(ip, timestamp, attrs \\ []) do
    base = %Event{
      timestamp: timestamp,
      ip: ip,
      method: "GET",
      path: "/",
      status: 200,
      bytes: 0,
      referer: "https://google.com",
      user_agent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
      raw: ""
    }

    struct(base, attrs)
  end

  def burst(ip, base_ts, count, interval_ms, attrs \\ []) do
    for i <- 0..(count - 1) do
      event(ip, DateTime.add(base_ts, i * interval_ms, :millisecond), attrs)
    end
  end
end
