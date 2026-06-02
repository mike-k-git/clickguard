defmodule Clickguard.PipelineGoldenTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Golden test. The fixture generator is :rand-seeded, so the full pipeline must
  yield exactly this set of findings. Guards against silent fixture/detector drift
  (the kind that let three keyword-mismatch bugs through unnoticed).

  Compared as a SORTED SET, not a list: finding order is unspecified
  (Task.async_stream is ordered: false, and each detector ends in group_by).
  An intentional generator/detector change means updating @expected.
  """

  @expected [
    {:high_frequency_ip, "127.0.0.1", 300},
    {:automation_tool, "10.0.0.1", 1},
    {:automation_tool, "10.0.0.2", 1},
    {:automation_tool, "10.0.0.10", 2},
    {:headless_browser, "10.0.0.10", 2},
    {:empty_ua, "10.0.0.10", 1},
    {:spam_referer, "192.168.1.1", 1},
    {:spam_referer, "192.168.1.2", 1},
    {:spam_referer, "192.168.1.10", 1},
    {:empty_referer, "192.168.1.10", 1}
  ]

  setup do
    path =
      Path.join(System.tmp_dir!(), "clickguard_golden_#{System.unique_integer([:positive])}.log")

    {_total, ^path} =
      Clickguard.Fixtures.generate(out: path, freqip: true, bad_ua: true, bad_referer: true)

    on_exit(fn -> File.rm(path) end)
    {:ok, path: path}
  end

  test "pipeline yields exactly the expected findings", %{path: path} do
    {:ok, findings} = Clickguard.run(path)

    actual =
      findings
      |> Enum.map(&{&1.rule, &1.subject, &1.evidence.event_count})
      |> Enum.sort()

    assert actual == Enum.sort(@expected)
  end

  test "evidence carries the matched values", %{path: path} do
    {:ok, findings} = Clickguard.run(path)

    find = fn rule, subject ->
      Enum.find(findings, &(&1.rule == rule and &1.subject == subject))
    end

    assert find.(:spam_referer, "192.168.1.1").evidence.matched_referers == [
             "brandedleadgeneration.com"
           ]

    assert find.(:spam_referer, "192.168.1.2").evidence.matched_referers == ["addshoppers.com"]
    assert find.(:empty_referer, "192.168.1.10").evidence.matched_referers == []

    assert Enum.sort(find.(:automation_tool, "10.0.0.10").evidence.matched_uas) ==
             Enum.sort(["Wget/1.21.4", "Go-http-client/2.0"])

    assert find.(:empty_ua, "10.0.0.10").evidence.matched_uas == []
  end
end
