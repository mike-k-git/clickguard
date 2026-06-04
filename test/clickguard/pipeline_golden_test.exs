defmodule Clickguard.PipelineGoldenTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Golden test. The fixture generator is :rand-seeded, so the full pipeline must
  yield exactly this set of scores.

  An intentional generator/detector change means updating @expected.
  """
  alias Clickguard.Score

  @expected [
    %Score{
      actor: {:ip, "10.0.0.1"},
      band: :clear,
      rule_summary: %{automation_tool: {:low, 1}},
      score: 1,
      total_events: 1,
      total_findings: 1
    },
    %Score{
      actor: {:ip, "10.0.0.10"},
      band: :suspect,
      rule_summary: %{
        automation_tool: {:low, 2},
        empty_ua: {:low, 1},
        headless_browser: {:low, 1}
      },
      score: 2,
      total_events: 4,
      total_findings: 3
    },
    %Score{
      actor: {:ip, "10.0.0.2"},
      band: :clear,
      rule_summary: %{automation_tool: {:low, 1}},
      score: 1,
      total_events: 1,
      total_findings: 1
    },
    %Score{
      actor: {:ip, "127.0.0.1"},
      band: :fraud,
      rule_summary: %{
        automation_tool: {:low, 1},
        headless_browser: {:low, 1},
        high_frequency_ip: {:low, 300},
        spam_referer: {:low, 1}
      },
      score: 4,
      total_events: 303,
      total_findings: 4
    },
    %Score{
      actor: {:ip, "192.168.1.1"},
      band: :clear,
      rule_summary: %{spam_referer: {:low, 1}},
      score: 1,
      total_events: 1,
      total_findings: 1
    },
    %Score{
      actor: {:ip, "192.168.1.10"},
      band: :clear,
      rule_summary: %{empty_referer: {:low, 1}, spam_referer: {:low, 1}},
      score: 1,
      total_events: 2,
      total_findings: 2
    },
    %Score{
      actor: {:ip, "192.168.1.2"},
      band: :clear,
      rule_summary: %{spam_referer: {:low, 1}},
      score: 1,
      total_events: 1,
      total_findings: 1
    }
  ]

  setup do
    path =
      Path.join(System.tmp_dir!(), "clickguard_golden_#{System.unique_integer([:positive])}.log")

    {_total, ^path} =
      Clickguard.Fixtures.generate(out: path, freqip: true, bad_ua: true, bad_referer: true)

    on_exit(fn -> File.rm(path) end)
    {:ok, path: path}
  end

  test "pipeline yields exactly the expected scores", %{path: path} do
    {:ok, scores} = Clickguard.run(path)

    assert Enum.sort(scores) == Enum.sort(@expected)
  end

  test "evidence carries the matched values", %{path: path} do
    {:ok, events} = Clickguard.parse(File.stream!(path))
    {:ok, findings} = Clickguard.detect(events)

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
