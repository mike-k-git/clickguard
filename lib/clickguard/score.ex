defmodule Clickguard.Score do
  @moduledoc """
  Score model created by scorer results.

  The list of scores is consumed by reporter.
  Bands are assigned on rule diversity and their base weight.
  """

  alias Clickguard.Finding

  @type band :: :clear | :suspect | :fraud

  @type t :: %__MODULE__{
          actor: {:ip | :source | :session, String.t()},
          total_findings: pos_integer(),
          total_events: pos_integer(),
          rule_summary: %{atom() => {Finding.severity(), non_neg_integer()}},
          band: band(),
          score: non_neg_integer()
        }

  @enforce_keys [:actor, :total_findings, :total_events, :rule_summary, :band, :score]
  defstruct [:actor, :total_findings, :total_events, :rule_summary, :band, :score]
end
