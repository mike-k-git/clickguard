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
      raw: ""
    }

    struct(base, attrs)
  end

  def burst(ip, base_ts, count, interval_ms) do
    for i <- 0..(count - 1) do
      event(ip, DateTime.add(base_ts, i * interval_ms, :millisecond))
    end
  end
end
