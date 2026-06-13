defmodule Clickguard.Parser.CLFTest do
  use ExUnit.Case, async: true
  doctest Clickguard.Parser.CLF

  alias Clickguard.Event
  alias Clickguard.Parser.CLF

  doctest Clickguard.Event

  @good_line ~s(127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] ) <>
               ~s("GET /apache_pb.gif HTTP/1.0" 200 2326 ) <>
               ~s("http://www.example.com/start.html" ) <>
               ~s("Mozilla/4.08 [en] \(Win98; I ;Nav\)")

  describe "parse/1 - happy path" do
    test "parses a canonical Combined Log Format line" do
      assert {:ok, e} = CLF.parse(@good_line)

      assert e.ip == {127, 0, 0, 1}
      assert e.method == "GET"
      assert e.path == "/apache_pb.gif"
      assert e.status == 200
      assert e.bytes == 2326
      assert e.referer == "http://www.example.com/start.html"
      assert e.user_agent == "Mozilla/4.08 [en] (Win98; I ;Nav)"
      assert e.raw == @good_line

      assert %DateTime{year: 2000, month: 10, day: 10, hour: 20, minute: 55, second: 36} =
               e.timestamp

      # 13:55:36 -0700 = 20:55:36 UTC
    end

    test "Common Log Format (no referer /UA) parses with nils" do
      line = ~s(10.0.0.1 - - [22/May/2026:10:00:00 +0000] "POST /api/x HTTP/1.1" 201 5)
      assert {:ok, e} = CLF.parse(line)
      assert e.referer == nil
      assert e.user_agent == nil
      assert e.bytes == 5
      assert e.method == "POST"
    end

    test "bytes field of \"-\" becomes 0" do
      line = ~s(8.8.8.8 - - [22/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 304 -)
      assert {:ok, %Event{bytes: 0}} = CLF.parse(line)
    end

    test "IPv6 addresses parse" do
      line =
        ~s(2001:db8::1 - - [22/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.0.0")

      assert {:ok, %Event{ip: ip}} = CLF.parse(line)
      assert tuple_size(ip) == 8
    end

    test "negative timezone offset converts correctly" do
      line = ~s(1.2.3.4 - - [01/Jan/2026:00:00:00 -0500] "GET / HTTP/1.1" 200 1)
      assert {:ok, %Event{timestamp: ts}} = CLF.parse(line)
      # 00:00 -0500 == 05:00 UTC
      assert ts.hour == 5
    end

    test "positive timezone offset converts correctly" do
      line = ~s(1.2.3.4 - - [01/Jan/2026:00:00:00 +0500] "GET / HTTP/1.1" 200 1)
      assert {:ok, %Event{timestamp: ts}} = CLF.parse(line)
      # 00:00 +0500 == 19:00 UTC
      assert ts.hour == 19
    end

    test "strips trailing newline from streamed lines" do
      line = ~s(8.8.8.8 - - [22/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1\n)
      assert {:ok, _} = CLF.parse(line)
    end

    test "referer of \"-\" is preserved as a string, not nil" do
      line =
        ~s(1.2.3.4 - - [22/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.0.0")

      assert {:ok, %Event{referer: "-"}} = CLF.parse(line)
    end
  end

  describe "parse/1 - error cases" do
    test "rejects an empty string" do
      assert {:error, :empty} = CLF.parse("")
    end

    test "rejects clearly malformed lines" do
      for bad <- [
            "this is not a log line at all",
            "127.0.0.1 missing brackets and quotes",
            ~s(127.0.0.1 - - [bad-timestamp] "GET / HTTP/1.1" 200 1)
          ] do
        assert match?({:error, _}, CLF.parse(bad)), "should reject: #{inspect(bad)}"
      end
    end

    test "non-integer status is reported" do
      line = ~s(127.0.0.1 - - [22/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 2XX 1)
      assert {:error, _} = CLF.parse(line)
    end

    test "rejects nil-IP" do
      nil_ip_line = ~s(0.0.0.0.0 - - [22/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1)

      assert {:error, {:bad_field, :ip}} = CLF.parse(nil_ip_line)
    end
  end
end
