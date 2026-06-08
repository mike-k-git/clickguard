defmodule Clickguard.Reporter do
  @moduledoc """
  Behaviour for reporters.

  Implementations:

    * `Clickguard.Reporter.Text` - plain text without styling, best for text files and terminal output.

  ## Implementing a reporter

    defmodule MyReporter do
      @behaviour Clickguard.Reporter

      @impl true
      def format(scores) do
        # ...
      end
    end
  """
  alias Clickguard.Score

  @callback format(scores :: [Score.t()]) :: iodata()

  @band_rank %{fraud: 0, suspect: 1, clear: 2}
  @spec sort([Score.t()]) :: [Score.t()]
  def sort(scores), do: Enum.sort_by(scores, &{@band_rank[&1.band], -&1.score})
end
