defmodule Clickguard.EventBuilder do
  @moduledoc false

  alias Clickguard.{Event, Fixtures}

  def event(ip, timestamp, attrs \\ []) do
    base = %Event{
      timestamp: timestamp,
      ip: ip,
      method: "GET",
      path: "/",
      status: 200,
      bytes: 0,
      referer: "https://google.com",
      # nondeterministic user-agent generator, prevents collisions between freq_ip and click_velocity detections
      user_agent: Fixtures.generate_random_ua(),
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
