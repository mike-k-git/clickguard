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

  def generate(opts \\ []) do
    lines = Keyword.get(opts, :lines, 500)
    out = Keyword.get(opts, :out, "test/fixtures/sample_clf.log")
    freqip = Keyword.get(opts, :freqip, false)

    :rand.seed(:exsss, 4711)

    good_lines =
      if lines >= 1 do
        for n <- 1..lines do
          ts =
            DateTime.add(@base_ts, n, :second)
            |> Calendar.strftime("[%d/%b/%Y:%H:%M:%S +0000]")

          clf_line(ts: ts)
        end
      else
        []
      end

    freqip_lines =
      if freqip do
        for n <- 0..299 do
          ip = "127.0.0.1"

          ts =
            DateTime.add(@base_ts, n * 200, :millisecond)
            |> Calendar.strftime("[%d/%b/%Y:%H:%M:%S +0000]")

          clf_line(ip: ip, ts: ts)
        end
      else
        []
      end

    # |> Enum.shuffle() |> Enum.join("\n")
    output = (freqip_lines ++ good_lines) |> Enum.join("\n")

    File.mkdir_p!(Path.dirname(out))
    File.write!(out, output)

    total = length(good_lines) + length(freqip_lines)

    {total, out}
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
    ua = Keyword.get_lazy(fields, :ua, &user_agent/0)
    ref = Keyword.get_lazy(fields, :ref, &referer/0)

    "#{ip} #{identity} #{username} #{ts} \"#{method} #{target} HTTP/#{http_version}\" #{response_code} #{size} \"#{ref}\" \"#{ua}\""
  end

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
end
