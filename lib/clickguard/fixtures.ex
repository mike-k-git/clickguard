defmodule Clickguard.Fixtures do
  @moduledoc """
  Generate events in Combined Log Format
      
  """
  @response_codes [200, 401, 201, 302]
  @http_versions ["1.0", "1.1", "2", "3"]
  @usernames ["-", "-", "-", "-", "user"]
  @targets ["/index.html", "/index.php", "/", "/admin-login", "/postback?aff_id=123&offer_id=321"]
  @methods ["GET", "POST"]
  @base_ts ~U[2026-01-01 00:00:00.00Z]
  @ts_format "[%d/%b/%Y:%H:%M:%S +0000]"
  @referers [
    "https://www.example.com/search?q=open+source+database+tools",
    "https://news.example.com/item?id=482942418",
    "https://example.com/questions/71231823190/how-to-parse-http-headers-in-python",
    "https://www.example.com/r/programming/comments/15k2x9p/best_orm_for_node/"
  ]
  @user_agents [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
  ]

  @bad_user_agents [
    "python-requests/2.31.0",
    "Mozilla/5.0 (Unknown; Linux i686) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34",
    "curl/8.4.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/143.0.7499.4 Safari/537.36",
    "Wget/1.21.4",
    "Go-http-client/2.0",
    ""
  ]

  # must stay in sync with Referer @default_spam_domains
  @bad_referers [
    "https://brandedleadgeneration.com/",
    "https://www.addshoppers.com",
    "https://7minuteworkout.com",
    ""
  ]

  def generate(opts \\ []) do
    lines = Keyword.get(opts, :lines, 500)
    out = Keyword.get(opts, :out, "test/fixtures/sample_clf.log")
    freqip = Keyword.get(opts, :freqip, false)
    bad_ua = Keyword.get(opts, :bad_ua, false)
    bad_referer = Keyword.get(opts, :bad_referer, false)
    velocity = Keyword.get(opts, :velocity, false)
    velocity_medium = Keyword.get(opts, :velocity_medium, false)
    velocity_mixed = Keyword.get(opts, :velocity_mixed, false)

    :rand.seed(:exsss, 4711)

    good_lines = if lines >= 1, do: generate_good_lines(lines), else: []
    freqip_lines = if freqip, do: generate_freqip_lines(), else: []
    bad_ua_lines = if bad_ua, do: generate_bad_ua_lines(), else: []
    bad_referer_lines = if bad_referer, do: generate_bad_referer_lines(), else: []
    velocity_lines = if velocity, do: generate_velocity_lines(), else: []
    velocity_medium_lines = if velocity_medium, do: generate_medium_velocity_lines(), else: []
    velocity_mixed_lines = if velocity_mixed, do: generate_mixed_velocity_lines(), else: []

    output =
      (freqip_lines ++
         good_lines ++
         bad_ua_lines ++
         bad_referer_lines ++ velocity_lines ++ velocity_medium_lines ++ velocity_mixed_lines)
      |> Enum.shuffle()
      |> Enum.join("\n")

    File.mkdir_p!(Path.dirname(out))
    File.write!(out, output)

    total =
      length(good_lines) + length(freqip_lines) + length(bad_ua_lines) + length(bad_referer_lines) +
        length(velocity_lines) + length(velocity_medium_lines) + length(velocity_mixed_lines)

    {total, out}
  end

  defp generate_good_lines(lines) do
    for n <- 1..lines, do: clf_line(ts: ts(n))
  end

  # ms spacing: sustained rate across the window, not a spike
  defp generate_freqip_lines do
    generate_random_uas(300)
    |> Enum.with_index()
    |> Enum.map(fn {ua, idx} ->
      clf_line(
        ip: "127.0.0.1",
        ts: DateTime.add(@base_ts, idx * 200, :millisecond) |> Calendar.strftime(@ts_format),
        user_agent: ua
      )
    end)
  end

  # 2s cadence: deltas 2000ms -> median 2000 (<= meduim_median, > high_median)
  # one click per second -> max_burst 1 < 5 -> :medium
  defp generate_medium_velocity_lines do
    cadence_lines("172.16.0.2", 8) ++ cadence_lines("172.16.0.3", 25)
  end

  defp cadence_lines(ip, n) do
    for i <- 1..n do
      clf_line(
        ip: ip,
        ts: DateTime.add(@base_ts, i * 2, :second) |> Calendar.strftime(@ts_format),
        user_agent: "medium-cadence-browser"
      )
    end
  end

  # 6-click same-second burst (median 0 -> :high) + 26 singles spaced 31 min apart:
  # each single is > session_gap_ms from its neighbour -> session of 1
  # -> filtered by min_session_clicks. event_count 6, pair total 32, ratio 0.19 < floor.
  defp generate_mixed_velocity_lines do
    burst =
      for _ <- 1..6,
          do: clf_line(ip: "172.16.0.4", ts: ts(0), user_agent: "burst-then-idle-browser")

    idle =
      for i <- 1..26 do
        clf_line(
          ip: "172.16.0.4",
          ts: DateTime.add(@base_ts, i * 31 * 60, :second) |> Calendar.strftime(@ts_format),
          user_agent: "burst-then-idle-browser"
        )
      end

    burst ++ idle
  end

  defp generate_velocity_lines do
    for n <- 1..25,
        do:
          clf_line(
            ip: "172.16.0.1",
            ts: DateTime.add(@base_ts, n, :second) |> Calendar.strftime(@ts_format),
            user_agent: "high-velocity-browser"
          )
  end

  defp generate_bad_ua_lines do
    [first, second, third | rest] = @bad_user_agents

    single_ua_per_ip = [
      clf_line(ip: "10.0.0.1", ts: ts(0), user_agent: first),
      clf_line(ip: "10.0.0.2", ts: ts(10), user_agent: third),
      clf_line(ip: "127.0.0.1", ts: ts(0), user_agent: first),
      clf_line(ip: "127.0.0.1", ts: ts(0), user_agent: second)
    ]

    multiple_ua_per_ip =
      for ua <- rest, do: clf_line(ip: "10.0.0.10", ts: ts(10), user_agent: ua)

    single_ua_per_ip ++ multiple_ua_per_ip
  end

  defp generate_bad_referer_lines do
    [first, second | rest] = @bad_referers

    single_ref_per_ip = [
      clf_line(ip: "192.168.1.1", ts: ts(0), referer: first),
      clf_line(ip: "192.168.1.2", ts: ts(10), referer: second),
      clf_line(ip: "127.0.0.1", ts: ts(10), referer: first)
    ]

    multiple_ref_per_ip =
      for ref <- rest, do: clf_line(ip: "192.168.1.10", ts: ts(10), referer: ref)

    single_ref_per_ip ++ multiple_ref_per_ip
  end

  defp clf_line(fields) do
    ip = Keyword.get_lazy(fields, :ip, &ip/0)
    identity = Keyword.get(fields, :identity, "-")
    username = Keyword.get_lazy(fields, :username, &username/0)
    ts = Keyword.get(fields, :ts, ~U[1970-01-01 00:00:00.00Z])
    method = Keyword.get_lazy(fields, :method, &method/0)
    target = Keyword.get_lazy(fields, :target, &target/0)
    http_version = Keyword.get_lazy(fields, :http_version, &http_version/0)
    response_code = Keyword.get_lazy(fields, :response_code, &response_code/0)
    size = Keyword.get_lazy(fields, :size, &size/0)
    ua = Keyword.get_lazy(fields, :user_agent, &user_agent/0)
    ref = Keyword.get_lazy(fields, :referer, &referer/0)

    "#{ip} #{identity} #{username} #{ts} \"#{method} #{target} HTTP/#{http_version}\" #{response_code} #{size} \"#{ref}\" \"#{ua}\""
  end

  defp ts(offset_s),
    do: DateTime.add(@base_ts, offset_s, :second) |> Calendar.strftime(@ts_format)

  defp username, do: Enum.random(@usernames)
  defp method, do: Enum.random(@methods)
  defp response_code, do: Enum.random(@response_codes)
  defp target, do: Enum.random(@targets)
  defp http_version, do: Enum.random(@http_versions)
  defp user_agent, do: Enum.random(@user_agents)
  defp referer, do: Enum.random(@referers)

  # CLF renders 0-byte responses as "-"
  defp size do
    case Enum.random(0..10_000) do
      0 -> "-"
      size -> size
    end
  end

  defp ip do
    for(
      _ <- 1..4,
      do: Enum.random(1..255)
    )
    |> Enum.join(".")
  end

  def generate_random_ua,
    do:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/#{Enum.random(1..150)}.#{Enum.random(1..10)}.#{Enum.random(1..10)}.#{Enum.random(1..10_000)} Safari/537.36"

  def generate_random_uas(n) do
    for _ <- 1..n, do: generate_random_ua()
  end
end
