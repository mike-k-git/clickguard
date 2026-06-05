defmodule Clickguard.Reporter.TextTest do
  use ExUnit.Case, async: true

  alias Clickguard.Reporter.Text
  alias Clickguard.Score

  describe "format/1 - sort order" do
    test "lines are correctly sorted by band" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{low_detection: {:low, 1}},
          band: :clear,
          score: 1
        },
        %Score{
          actor: {:ip, "127.0.0.2"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{medium_detection: {:medium, 1}},
          band: :suspect,
          score: 3
        },
        %Score{
          actor: {:ip, "127.0.0.3"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{high_detection: {:high, 1}},
          band: :fraud,
          score: 16
        }
      ]

      assert [_header, l1, l2, l3] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "fraud")
      assert String.contains?(l2, "suspect")
      assert String.contains?(l3, "clear")
    end

    test "lines are correctly sorted by score inside bands" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{high_detection: {:high, 1}},
          band: :fraud,
          score: 16
        },
        %Score{
          actor: {:ip, "127.0.0.2"},
          total_findings: 2,
          total_events: 2,
          rule_summary: %{high_detection: {:high, 1}, another_high_detection: {:high, 1}},
          band: :fraud,
          score: 32
        }
      ]

      assert [_header, l1, l2] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "32")
      assert String.contains?(l2, "16")
    end
  end

  describe "format/1 - severity summary" do
    test "includes only present severities" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 2,
          total_events: 2,
          rule_summary: %{high_detection: {:high, 1}, low_detection: {:low, 1}},
          band: :fraud,
          score: 17
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "high: 1")
      assert String.contains?(l1, "low: 1")
      refute String.contains?(l1, "medium: 0")
    end

    test "severities are correctly sorted" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 3,
          total_events: 3,
          rule_summary: %{
            high_detection: {:high, 1},
            low_detection: {:low, 1},
            medium_detection: {:medium, 1}
          },
          band: :fraud,
          score: 20
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "high: 1, medium: 1, low: 1")
    end

    test "single severity is correctly displayed" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{
            medium_detection: {:medium, 1}
          },
          band: :fraud,
          score: 3
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "\tmedium: 1\t")
    end
  end

  describe "format/1 - worst rule selection" do
    test "single :medium finding outranks 1000 :low" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1001,
          total_events: 10_010,
          rule_summary: %{
            medium_detection: {:medium, 1},
            low_detection: {:low, 1000}
          },
          band: :fraud,
          score: 1003
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "\t:medium_detection (1)")
    end

    test "within the same severity, higher rule_finding wins" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1001,
          total_events: 10_010,
          rule_summary: %{
            medium_detection_one: {:medium, 1},
            medium_detection_two: {:medium, 1000}
          },
          band: :fraud,
          score: 3003
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "\t:medium_detection_two (1000)")
    end
  end

  describe "format/1 - edge cases" do
    test "empty scores list returns just the header" do
      assert Text.format([]) |> IO.iodata_to_binary() |> String.split("\n", trim: true) ==
               ["actor\tevents\tband\tscore\tsummary\tworst"]
    end

    test "actor with only hygiene rules is formatted correctly" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{
            low_detection: {:low, 1}
          },
          band: :clear,
          score: 0
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.contains?(l1, "clear")
    end
  end

  describe "format/1 - output structure" do
    test "header is the first row" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{low_detection: {:low, 1}},
          band: :clear,
          score: 1
        },
        %Score{
          actor: {:ip, "127.0.0.2"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{medium_detection: {:medium, 1}},
          band: :suspect,
          score: 3
        },
        %Score{
          actor: {:ip, "127.0.0.3"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{high_detection: {:high, 1}},
          band: :fraud,
          score: 16
        }
      ]

      assert [header | _rest] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert header == "actor\tevents\tband\tscore\tsummary\tworst"
    end

    test "actor is well-formatted" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{
            low_detection: {:low, 1}
          },
          band: :clear,
          score: 0
        }
      ]

      assert [_header, l1] =
               Text.format(scores) |> IO.iodata_to_binary() |> String.split("\n", trim: true)

      assert String.starts_with?(l1, "ip:127.0.0.1")
    end
  end
end
