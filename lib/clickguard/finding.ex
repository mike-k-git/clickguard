defmodule Clickguard.Finding do
  @moduledoc """
  Finding model created by detector results.

  All detectors produce a list of `%Finding{}` values; all report builders consume them.
  """
  alias Clickguard.Event
  @type severity :: :low | :medium | :high

  @type t :: %__MODULE__{
          rule: atom(),
          severity: severity(),
          subject: String.t(),
          actor_type: :ip | :source | :session,
          evidence: map(),
          sample_events: [Event.t()],
          detected_at: DateTime.t()
        }

  @enforce_keys [:rule, :severity, :subject, :actor_type, :detected_at]
  defstruct [:rule, :severity, :subject, :actor_type, :evidence, :sample_events, :detected_at]
end
